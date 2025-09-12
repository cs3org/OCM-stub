<p align="center">
  <img src="https://github.com/cs3org/OCM-API/blob/develop/logo/OpenCloudMesh-text-vertical-300x116.png" alt="Open Cloud Mesh Logo"/>
</p>

# OCM Stub

A Stub server for testing the Open Cloud Mesh (OCM) Protocol Specification, maintained at https://github.com/cs3org/OCM-API

Run with:

```sh
mkdir -p ../tls
openssl req -new -x509 -days 365 -nodes \
  -out ../tls/server.crt \
  -keyout ../tls/server.key \
  -subj "/C=RO/ST=Bucharest/L=Bucharest/O=IT/CN=www.example.ro"
NODE_TLS_REJECT_UNAUTHORIZED=0 SERVER_HOST=localhost node stub.js 
```

Then visit for instance:
* https://localhost/ocm-provider/
* https://localhost/shareWith?bob@localhost
