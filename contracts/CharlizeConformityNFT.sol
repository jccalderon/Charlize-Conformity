// SPDX-License-Identifier: MIT

/// @title Charlize - Conformity NFT
/// @author Jairo Malaver, Juan Calderon
/// @notice Identity Access Managmenent (IAM)
/// @dev In the process of verification of certificates of
/// users validate their access to the app either to submit certificates 
/// of conformity or follow up their verification process
/// @custom:experimental This is prototype.
pragma solidity 0.8.20;

import "@openzeppelin/contracts@4.9.1/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts@4.9.1/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts@4.9.1/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts@4.9.1/token/ERC721/extensions/ERC721Burnable.sol";
import "@openzeppelin/contracts@4.9.1/access/Ownable.sol";
import "@openzeppelin/contracts@4.9.1/utils/Counters.sol";

contract ConformityNFT is ERC721, ERC721Enumerable, ERC721URIStorage, ERC721Burnable, Ownable {
    using Counters for Counters.Counter;

    Counters.Counter private _tokenIdCounter;

    constructor() ERC721("ConformityNFT", "CTK") {}

    function _baseURI() internal pure override returns (string memory) {
        return "https://<>";
    }

    function safeMint(address to, string memory uri) public onlyOwner {
        uint256 tokenId = _tokenIdCounter.current();
        _tokenIdCounter.increment();
        _safeMint(to, tokenId);
        _setTokenURI(tokenId, uri);
    }

    // The following functions are overrides required by Solidity.

    function _beforeTokenTransfer(address from, address to, uint256 tokenId, uint256 batchSize)
        internal
        override(ERC721, ERC721Enumerable)
    {
        super._beforeTokenTransfer(from, to, tokenId, batchSize);
    }

    function _burn(uint256 tokenId) internal override(ERC721, ERC721URIStorage) {
        super._burn(tokenId);
    }

    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC721Enumerable, ERC721URIStorage)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
