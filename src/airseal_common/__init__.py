"""AirSeal common utilities and cryptography."""

from .crypto import (
    KeyPair,
    TrustStore,
    NonceManager,
    NonceData,
    Manifest,
    ImportReceipt,
    ManifestSigner,
    ManifestVerifier,
    ReceiptSigner,
    compute_file_hash,
)

from .policy import (
    SecurityPolicy,
    PolicyEngine,
    PolicyStore,
    DEFAULT_POLICY,
    HIGH_SECURITY_POLICY,
    PERMISSIVE_POLICY,
)

from .scanner import (
    ScanResult,
    FileScanner,
    WindowsDefenderScanner,
    ClamAVScanner,
    DemoScanner,
    ScannerFactory,
)

from .qr import (
    QRCodeGenerator,
    QRCodeParser,
    NonceQRData,
    ManifestQRData,
    ReceiptQRData,
    estimate_qr_size,
    compress_manifest_for_qr,
    decompress_manifest_from_qr,
)

__all__ = [
    # Crypto
    "KeyPair",
    "TrustStore",
    "NonceManager",
    "NonceData",
    "Manifest",
    "ImportReceipt",
    "ManifestSigner",
    "ManifestVerifier",
    "ReceiptSigner",
    "compute_file_hash",
    # Policy
    "SecurityPolicy",
    "PolicyEngine",
    "PolicyStore",
    "DEFAULT_POLICY",
    "HIGH_SECURITY_POLICY",
    "PERMISSIVE_POLICY",
    # Scanner
    "ScanResult",
    "FileScanner",
    "WindowsDefenderScanner",
    "ClamAVScanner",
    "DemoScanner",
    "ScannerFactory",
    # QR
    "QRCodeGenerator",
    "QRCodeParser",
    "NonceQRData",
    "ManifestQRData",
    "ReceiptQRData",
    "estimate_qr_size",
    "compress_manifest_for_qr",
    "decompress_manifest_from_qr",
]
