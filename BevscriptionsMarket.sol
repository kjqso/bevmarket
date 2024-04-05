// SPDX-License-Identifier: MIT
pragma solidity ^0.8.8;

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v4.0/contracts/access/Ownable.sol";
import "solady/src/utils/SafeTransferLib.sol";
import "solady/src/utils/ECDSA.sol";
import "solady/src/utils/EIP712.sol";
import "@solidstate/contracts/security/reentrancy_guard/ReentrancyGuard.sol";

struct BM20Order {
    address seller; // signer of the bm20 token seller
    bytes32 listId;
    string ticker; 
    uint256 amount;
    uint256 price;
    uint64 listingTime; // startTime in timestamp
    uint64 expirationTime; // endTime in timestamp
    uint16 feeRate;
    uint32 salt; //9-digit
    bytes signature;
}

library OrderTypes {
    bytes32 internal constant BM20_ORDER_HASH =
        keccak256(
            "Listing(address seller,bytes32 listId,string ticker,uint256 amount,uint256 price,uint64 listingTime,uint64 expirationTime,uint16 feeRate,uint32 salt)"
        );
           
    function hash(BM20Order memory order) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    BM20_ORDER_HASH,
                    order.seller,
                    order.listId,
                    keccak256(bytes(order.ticker)),
                    order.amount,
                    order.price,
                    order.listingTime,
                    order.expirationTime,
                    order.feeRate,
                    order.salt
                )
            );
    }
}

contract BevscriptionsMarket is Ownable, ReentrancyGuard, EIP712 {
    
    using SafeTransferLib for address;
    using ECDSA for bytes32;
    using OrderTypes for BM20Order;

    error InvalidSignature();
    error FeatureDisabled();
    error NoOrdersMatched();
    error MsgValueInvalid();

    event protocol_TransferBM20TokenForListing(
        address indexed from,
        address indexed to,
        bytes32 listId
    );

    event BM20OrderPurchased(
        address indexed seller,
        address indexed buyer,
        uint256 amount,
        uint256 price,
        bytes32 listId
    );
    event BM20OrderCanceled(address indexed seller, bytes32 indexed listId);
                
    event FeeBpsChanged(uint96 oldFeeBps, uint96 newFeeBps);

    mapping(address => mapping(bytes32 => bool)) private userListingCancellations;
            
    uint96 public feeBps;
    address payable public feeAddress;
    mapping(string => bool) featureIsEnabled;
    address public trustedVerifier;

    constructor(uint96 fee, address _feeAddress, address _trustedVerifier) {

        feeBps = fee;
        feeAddress = payable(_feeAddress);
        featureIsEnabled['buy'] = true;
        featureIsEnabled['cancel'] = true;
        trustedVerifier = _trustedVerifier;

    }

    function batchMatchOrders(BM20Order[] calldata orders) public payable nonReentrant {
        if (!featureIsEnabled['buy']) revert FeatureDisabled();

        require(orders.length <= 20, "Too much orders");
        uint16 matched = 0; 
        uint256 userBalance = msg.value;
        for (uint i=0; i<orders.length; i++) {
            BM20Order calldata order = orders[i];
                     
            uint256 orderAmount = order.price * order.amount * 10 ** 10;
            require(userBalance >= orderAmount, "Insufficient balance");
            userBalance -= orderAmount;

            _executeOrder(order, orderAmount);
            
            matched++;
        }
        if (matched == 0) {
            revert NoOrdersMatched();
        }

        // refund balance
        if (userBalance > 0) {
            payable(msg.sender).transfer(userBalance);
        }
    }
    function executeOrder(BM20Order calldata order) public payable {

        _executeOrder(order, msg.value);
    }
    function _executeOrder(BM20Order calldata order, uint256 userBalance) internal {
        if (!featureIsEnabled['buy']) revert FeatureDisabled();
        uint256 toBePaid = order.price * order.amount * 10 ** 10;
        if (toBePaid != userBalance) {
            revert MsgValueInvalid();
        }
 
        bytes32 orderHash = _hashTypedData(order.hash());
        address signer = orderHash.recoverCalldata(order.signature);

        if (
            signer != order.seller ||
            block.timestamp < order.listingTime ||
            block.timestamp > order.expirationTime ||
            userListingCancellations[order.seller][order.listId]
        ) {
            revert InvalidSignature();
        }

        uint256 fee = computeFee(toBePaid);
        if (fee > 0) {
            feeAddress.transfer(fee);
        }
        payable(order.seller).transfer(toBePaid - fee);
                
        userListingCancellations[order.seller][order.listId] = true;

        emit BM20OrderPurchased(order.seller, msg.sender, order.amount, order.price, order.listId);
        emit protocol_TransferBM20TokenForListing(order.seller, msg.sender, order.listId);
    }

    function cancelOrders(BM20Order[] calldata orders) public {
        if (!featureIsEnabled['cancel']) revert FeatureDisabled();

        for (uint8 i = 0; i < orders.length; i++) {
            BM20Order calldata order = orders[i];

            cancelOrder(order);
        }
    }
    function cancelOrder(BM20Order calldata order) public {
        if (!featureIsEnabled['cancel']) revert FeatureDisabled();

        bytes32 orderHash = _hashTypedData(order.hash());
        address signer = orderHash.recoverCalldata(order.signature);
        require(signer == msg.sender, "Can only be called by the sender");

        if (signer != order.seller || userListingCancellations[order.seller][order.listId]) {
            revert InvalidSignature();
        }
 
        userListingCancellations[order.seller][order.listId] = true;

        emit BM20OrderCanceled(order.seller, order.listId);
        emit protocol_TransferBM20TokenForListing(order.seller, order.seller, order.listId);

    }
    function refundOrders(BM20Order[] calldata orders) public {
        if (!featureIsEnabled['cancel']) revert FeatureDisabled();

        for (uint8 i = 0; i < orders.length; i++) {
            BM20Order calldata order = orders[i];

            refund(order);
        }
    }
    function refund(BM20Order calldata order) public {
        if (!featureIsEnabled['cancel']) revert FeatureDisabled();

        bytes32 orderHash = _hashTypedData(order.hash());
        address signer = orderHash.recoverCalldata(order.signature);

        if (signer != trustedVerifier || userListingCancellations[order.seller][order.listId]) {
            revert InvalidSignature();
        }
 
        userListingCancellations[order.seller][order.listId] = true;

        emit BM20OrderCanceled(order.seller, order.listId);
        emit protocol_TransferBM20TokenForListing(order.seller, order.seller, order.listId);

    }
    function updateTrustedVerifier(address _trustedVerifier) external onlyOwner {
        trustedVerifier = _trustedVerifier;
    }
    function setFeatureStatus(string memory feature, bool enabled) internal {
        
        featureIsEnabled[feature] = enabled;
    }
    
    function enableFeature(string memory feature) public onlyOwner {

        setFeatureStatus(feature, true);
    }

    function disableFeature(string memory feature) public onlyOwner {

        setFeatureStatus(feature, false);
    }

    function enableAllFeatures() external onlyOwner {

        enableFeature("buy");
        enableFeature("cancel");
    }
    
    function disableAllFeatures() external onlyOwner {

        disableFeature("buy");
        disableFeature("cancel");
    }
    
    
    function computeFee(uint256 amount) public view returns (uint256) {
        return (amount * feeBps) / 10000;
    }
    
    function getFeeBps() external view returns (uint256) {
        return feeBps;
    }
    function setFeeBps(uint96 fee) external onlyOwner {
        require(fee <= 3000, "Out of limits");

        emit FeeBpsChanged(feeBps, fee);
        
        feeBps = fee;
    }
    function setFeeAddress(address _feeAddress) external onlyOwner {

        feeAddress =  payable(_feeAddress);
    }

    fallback() external {}

    function _domainNameAndVersion() 
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "Bevscriptions Market";
        version = "1";
    }
}
