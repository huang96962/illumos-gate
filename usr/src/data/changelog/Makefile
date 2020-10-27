include $(SRC)/data/Makefile.data

MODULE_NAME = changelog

CHGLOG_FILE_NAME = changelog

CLOBBERFILES += files/changelog

ROOT_MOD_DIR = $(ROOT)/etc

CHGLOG_FILES_DIR = $(SRC)/data/$(MODULE_NAME)/files

$(ROOT_MOD_DIR)/%:	$(CHGLOG_FILES_DIR)/% $(ROOT_MOD_DIR)
	$(INS.file)

$(MODULE_NAME)/git:
	mkdir -p $(CHGLOG_FILES_DIR); \
	git log --no-merges --max-count=10 --pretty=reference --author='marstor' \
        > $(CHGLOG_FILES_DIR)/$(CHGLOG_FILE_NAME);

all: build install

build: $(MODULE_NAME)/git

install: build $(ROOT_MOD_DIR)/changelog

clean:

include $(SRC)/data/Makefile.targ
