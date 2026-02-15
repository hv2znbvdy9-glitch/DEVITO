"""
AVA gRPC Protocol Buffer Definitions

Dieses Paket enthält die kompilierten Protocol Buffer Definitionen für
den AVA gRPC Service.

Verwendung:
    from ava.api.proto import ava_service_pb2, ava_service_pb2_grpc

Hinweis:
    Die *_pb2.py und *_pb2_grpc.py Dateien werden automatisch generiert
    aus ava_service.proto mittels:
        make proto-compile
    oder:
        python -m grpc_tools.protoc --proto_path=. --python_out=. --grpc_python_out=. ava_service.proto
"""

__all__ = [
    "ava_service_pb2",
    "ava_service_pb2_grpc",
]

# Proto-Module werden erst nach Compilation verfügbar
try:
    from . import ava_service_pb2
    from . import ava_service_pb2_grpc
except ImportError:
    import warnings
    warnings.warn(
        "Proto files not compiled yet. Run 'make proto-compile' to generate them.",
        ImportWarning
    )
