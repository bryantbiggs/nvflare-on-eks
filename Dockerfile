FROM python:3.8-buster

RUN python3 -m pip install -e git+https://git@github.com/NVIDIA/NVFlare.git@dev#egg=nvflare-nightly
