# Tenarium operator. Run from the operator/ directory.
IMG ?= tenarium-operator:dev
CONTROLLER_GEN_VERSION ?= v0.22.0
ENVTEST_K8S_VERSION ?= 1.37.0
LOCALBIN ?= $(CURDIR)/bin
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
SETUP_ENVTEST ?= $(LOCALBIN)/setup-envtest

.PHONY: all
all: generate manifests build

.PHONY: build
build: ## Build the manager binary.
	go build -o $(LOCALBIN)/manager ./cmd

.PHONY: run
run: ## Run against the current kubeconfig (set TENARIUM_URL / TENARIUM_API_KEY).
	go run ./cmd

.PHONY: generate
generate: $(CONTROLLER_GEN) ## Generate deepcopy code.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./api/v1alpha1"

.PHONY: manifests
manifests: $(CONTROLLER_GEN) ## Generate CRDs and the ClusterRole.
	$(CONTROLLER_GEN) rbac:roleName=tenarium-operator crd paths="./api/v1alpha1;./internal/controller" \
		output:crd:artifacts:config=config/crd/bases output:rbac:artifacts:config=config/rbac

.PHONY: test
test: ## Unit tests (fake Kubernetes client + in-process Tenarium server).
	go test ./...

.PHONY: test-envtest
test-envtest: $(SETUP_ENVTEST) ## Also run the envtest suite (Linux/macOS).
	KUBEBUILDER_ASSETS="$$($(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" \
		go test -tags envtest ./...

.PHONY: test-envtest-docker
test-envtest-docker: ## Run the envtest suite in a Linux container (e.g. on Windows).
	docker run --rm -v "$(abspath ..):/src:ro" -w /src/operator \
		-v tenarium-operator-gomod:/go/pkg/mod -v tenarium-operator-cache:/root/.cache \
		golang:1.26 sh -c 'export GOFLAGS=-buildvcs=false; \
		go install sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.23 && \
		KUBEBUILDER_ASSETS="$$(setup-envtest use $(ENVTEST_K8S_VERSION) --bin-dir /root/.cache/envtest -p path)" \
		go test -tags envtest -count=1 ./...'

.PHONY: docker-build
docker-build: ## Build the image (context is the repository root).
	docker build -f Dockerfile -t $(IMG) ..

.PHONY: install
install: ## Install the CRDs into the current cluster.
	kubectl apply -k config/crd

.PHONY: deploy
deploy: ## Deploy CRDs, RBAC and the manager.
	kubectl apply -k config/default

.PHONY: undeploy
undeploy:
	kubectl delete -k config/default

$(CONTROLLER_GEN):
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

$(SETUP_ENVTEST):
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.23
