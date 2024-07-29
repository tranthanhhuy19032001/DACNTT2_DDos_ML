# DACNTT2_DDos_ML
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

cd ryu/ryu/controller/DACNTT2_DDos_ML/FinalVersion/controller

cd mininet/mininet/DACNTT2_DDos_ML/FinalVersion/mininet

python3 -m http.server 80 &

siege -c 100 -t 1M http://192.168.0.1
