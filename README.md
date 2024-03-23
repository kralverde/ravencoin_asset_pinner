# Ravencoin Asset Pinner

A script to walk the ravencoin blockchain, pinning asset CIDs to
a local IFPS node as they are found.

Environment Variables:
`DAEMON_URL`: the url/ip of the ravencoin daemon. Defaults to `127.0.0.1`.
`DAEMON_PORT`: the port of the ravencoin daemon rpc. Defaults to `8766`.
`DAEMON_USERNAME`: the rpc username.
`DAEMON_PASSWORD`: the rpc password.
`IPFS_URL`: the url/ip of the IPFS daemon. Defaults to `127.0.0.1`.
`IPFS_PORT`: the port of the IPFS daemon. Defaults to `5001`.
