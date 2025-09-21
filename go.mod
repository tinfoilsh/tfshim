module github.com/tinfoilsh/tfshim

go 1.25.0

require (
	github.com/NVIDIA/go-nvml v0.13.0-1
	github.com/creasty/defaults v1.8.0
	github.com/go-acme/lego/v4 v4.23.1
	github.com/google/go-sev-guest v0.12.1
	github.com/google/go-tdx-guest v0.3.1
	github.com/jarcoal/httpmock v1.3.1
	github.com/klauspost/cpuid/v2 v2.2.10
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.11.1
	github.com/tinfoilsh/stransport v0.0.0-20250918191641-357d27da6b0b
	github.com/tinfoilsh/verifier v0.1.18
	golang.org/x/time v0.12.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/cloudflare/cloudflare-go v0.115.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-jose/go-jose/v4 v4.1.2 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	github.com/google/go-containerregistry v0.20.6 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/letsencrypt/boulder v0.20250902.0 // indirect
	github.com/mackerelio/go-osstat v0.2.6 // indirect
	github.com/miekg/dns v1.1.64 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.9.1 // indirect
	github.com/sigstore/protobuf-specs v0.5.0 // indirect
	github.com/sigstore/sigstore v1.9.6-0.20250729224751-181c5d3339b3 // indirect
	github.com/theupdateframework/go-tuf/v2 v2.1.1 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/mod v0.27.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/term v0.35.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	golang.org/x/tools v0.36.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250826171959-ef028d996bc1 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250826171959-ef028d996bc1 // indirect
	google.golang.org/grpc v1.75.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	marwan.io/wasm-fetch v0.1.0 // indirect
)

replace github.com/google/go-sev-guest => github.com/tinfoilsh/go-sev-guest v0.0.0-20250704193550-c725e6216008
