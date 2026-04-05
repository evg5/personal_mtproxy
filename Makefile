DESTDIR:=
prefix:=$(DESTDIR)/opt
REBAR3:=rebar3
SERVICE:=$(DESTDIR)/etc/systemd/system/personal_mtproxy.service
LOGDIR:=$(DESTDIR)/var/log/personal_mtproxy
DATADIR:=$(DESTDIR)/var/lib/personal_mtproxy
USER:=personal_mtproxy

DEV_CERT_DIR := priv/certs
DEV_CERT     := $(DEV_CERT_DIR)/cert.pem
DEV_KEY      := $(DEV_CERT_DIR)/key.pem
DEV_DOMAIN   := demo.personal-mtp.test

all: config/sys.config config/vm.args
	$(REBAR3) as prod release

.PHONY: test
test:
	$(REBAR3) ct

config/sys.config: config/sys.config.example
	[ -f $@ ] || cp $^ $@

config/vm.args: config/vm.args.example
	[ -f $@ ] || cp $^ $@

.PHONY: dev-certs
dev-certs: $(DEV_CERT)

$(DEV_CERT):
	mkdir -p $(DEV_CERT_DIR)
	openssl req -x509 -newkey rsa:2048 -keyout $(DEV_KEY) -out $(DEV_CERT) \
	  -days 3650 -nodes \
	  -subj "/CN=$(DEV_DOMAIN)" \
	  -addext "subjectAltName=DNS:$(DEV_DOMAIN)"

.PHONY: dev-hosts
dev-hosts:
	grep -qF "$(DEV_DOMAIN)" /etc/hosts || \
	  echo "127.0.0.1 $(DEV_DOMAIN)  # personal_mtproxy dev" | sudo tee -a /etc/hosts

.PHONY: dev
dev: dev-certs dev-hosts
	$(REBAR3) as dev shell --config config/local.sys.config

.PHONY: clean
clean:
	sudo sed -i "/# personal_mtproxy dev$$/d" /etc/hosts
	rm -rf $(DEV_CERT_DIR)
	$(REBAR3) clean

user:
	sudo useradd -r $(USER) || true

$(LOGDIR):
	mkdir -p $(LOGDIR)/
	chown $(USER) $(LOGDIR)/

$(DATADIR):
	mkdir -p $(DATADIR)/
	chown $(USER) $(DATADIR)/

install: user $(LOGDIR) $(DATADIR)
	mkdir -p $(prefix)
	cp -r _build/prod/rel/personal_mtproxy $(prefix)/
	mkdir -p $(prefix)/personal_mtproxy/log/
	chmod 777 $(prefix)/personal_mtproxy/log/
	install -D config/personal-mtproxy.service $(SERVICE)
	systemctl daemon-reload

.PHONY: update-sysconfig
update-sysconfig: config/sys.config $(prefix)/personal_mtproxy
	REL_VSN=$$(cat $(prefix)/personal_mtproxy/releases/start_erl.data | cut -d " " -f 2) && \
		install -m 644 config/sys.config "$(prefix)/personal_mtproxy/releases/$${REL_VSN}/sys.config"

uninstall:
	rm $(SERVICE)
	rm -r $(prefix)/personal_mtproxy
	systemctl daemon-reload
