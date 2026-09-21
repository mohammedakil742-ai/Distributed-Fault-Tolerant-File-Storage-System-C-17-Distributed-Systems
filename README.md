# Distributed Fault-Tolerant File Storage System — C++17

A complete educational distributed file-storage project using only the C++17 standard library and OS sockets.

## Features
- 3-node cluster
- HTTP REST API implemented directly with sockets
- File chunking (1 MiB)
- SHA-256 content addressing
- 3-way replication
- Deduplication
- Health/heartbeat monitoring
- Replica-aware download
- File metadata persistence
- Snapshot/version endpoint
- Web dashboard
- Docker deployment

## Build

Linux/macOS:
```bash
mkdir build && cd build
cmake ..
cmake --build . -j
```

Run three nodes from the project root:
```bash
./build/storage_node --id node1 --port 8081 --data data/node1 --peers http://127.0.0.1:8082,http://127.0.0.1:8083
./build/storage_node --id node2 --port 8082 --data data/node2 --peers http://127.0.0.1:8081,http://127.0.0.1:8083
./build/storage_node --id node3 --port 8083 --data data/node3 --peers http://127.0.0.1:8081,http://127.0.0.1:8082
```

Open:
http://127.0.0.1:8081

## API

Health:
```bash
curl http://127.0.0.1:8081/internal/health
```

Cluster:
```bash
curl http://127.0.0.1:8081/api/cluster
```

List:
```bash
curl http://127.0.0.1:8081/api/files
```

Upload:
```bash
curl -X POST --data-binary @example.txt -H "X-Filename: example.txt" http://127.0.0.1:8081/api/files
```

Download:
```bash
curl http://127.0.0.1:8081/api/files/<file-id> -o restored.bin
```

Snapshot:
```bash
curl -X POST http://127.0.0.1:8081/api/files/<file-id>/snapshot
```

## Windows
Build with Visual Studio CMake or:
```powershell
cmake -S . -B build
cmake --build build --config Release
```

## Architecture

Client -> Coordinator -> Storage Nodes

Every file is split into 1 MiB chunks. Each chunk is addressed by SHA-256. The coordinator stores each chunk on healthy nodes and attempts a replication factor of 3. During download, the coordinator can retrieve a missing local chunk from another healthy node.

## Resume description

Built a C++17 distributed fault-tolerant file storage system with 1 MiB chunking, SHA-256 content addressing, 3-way replication, deduplication, node health monitoring, replica-aware retrieval, metadata persistence and a browser dashboard.
