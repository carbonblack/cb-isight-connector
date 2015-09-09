#!/bin/bash

if [ "$(id -u)" == "0" ]; then
    sudo -u cb /usr/share/cb/integrations/isight/isight $@
    exit 0
fi
