
sudo docker exec trudi-victim bash -c 'cp /bin/sleep /tmp/.kworkerd; setsid /tmp/.kworkerd 3600 </dev/null >/dev/null 2>&1 &'

sudo docker exec trudi-victim bash -c 'setsid python3 -c "import time;d=\"TRUDI_DEMO_INJECTED_MARKER_C0FFEE\"*200;time.sleep(3600)" </dev/null >/dev/null 2>&1 &'

sudo docker exec trudi-victim /attacks/run persistence

sudo docker exec trudi-victim /attacks/run beacon

sudo docker exec trudi-victim sh -c 'ss -tn state established | grep 203.0.113.10'   # expect ESTABLISHED

