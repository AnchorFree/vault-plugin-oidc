all: docker run

docker:
	docker build -t vault-oidc -f build/package/Dockerfile  .

run: clean
	docker run -d -e VAULT_DEV_ROOT_TOKEN_ID="root" --name=vault vault-oidc
	docker exec -i -t vault /bin/sh -c "sleep 1; vault login root"
	docker exec -i -t vault /bin/sh -c ' \
	     vault write sys/plugins/catalog/oidc \
  		 sha_256=`sha256sum "/vault/plugin/$$OIDC_PLUGIN_BINARY" | cut -d " " -f1` \
  		 command=$$OIDC_PLUGIN_BINARY'
	docker exec -i -t vault /bin/sh -c 'vault secrets enable -plugin-name=oidc plugin'

clean: 
	docker rm -f vault
