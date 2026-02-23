#!/bin/bash
# install_magma_ezr.sh - Install and run EZR Fuzzer entirely inside Docker
set -e

echo "=========================================="
echo "Installing Magma + EZR Fuzzer (Docker)"
echo "=========================================="
echo ""

# -----------------------------------------------------------------------
# Check for Docker
# -----------------------------------------------------------------------
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    sudo apt-get update
    sudo apt-get install -y docker.io docker-compose
    sudo usermod -aG docker $USER
    echo "⚠ Docker installed. Log out and back in, then re-run this script."
    exit 0
fi

# -----------------------------------------------------------------------
# Step 1: Build Magma libpng image
# -----------------------------------------------------------------------
echo "Step 1: Build Magma libpng image with AFL++"
echo "This will take 30-60 minutes on first run..."
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/magma/tools/captain"

TARGET=libpng FUZZER=aflplusplus ./build.sh
echo "✓ magma/aflplusplus/libpng image built"
echo ""

# Optionally build more targets
read -p "Build more targets? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    for target in libtiff libxml2 sqlite3; do
        echo "Building $target..."
        TARGET=$target FUZZER=aflplusplus ./build.sh
        echo "✓ $target built"
    done
fi

# -----------------------------------------------------------------------
# Step 2: Build EZR Fuzzer Docker image
# -----------------------------------------------------------------------
echo ""
echo "Step 2: Build EZR Fuzzer Docker image..."
echo ""

cd "$SCRIPT_DIR"

if [ ! -f "ezr_magma_fuzzer.py" ]; then
    echo "ERROR: ezr_magma_fuzzer.py not found in $SCRIPT_DIR"
    exit 1
fi

cat > Dockerfile.ezr << 'DOCKERFILE'
FROM magma/aflplusplus/libpng

USER root

ENV DEBIAN_FRONTEND=noninteractive

# ---- Nuke the old venv so it can't interfere ----
RUN rm -rf /opt/venv

# ---- System deps ----
RUN apt-get update && apt-get install -y \
    python3.7 \
    python3.7-dev \
    python3.7-distutils \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# ---- Install pip for python3.7 ----
RUN wget https://bootstrap.pypa.io/pip/3.7/get-pip.py && \
    python3.7 get-pip.py && \
    rm get-pip.py

# ---- Install Rust (needed for tokenizers) ----
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# ---- Install Python deps using python3.7 explicitly ----
RUN python3.7 -m pip install --upgrade pip setuptools setuptools-rust wheel
RUN python3.7 -m pip install \
    torch==1.13.1 \
    numpy \
    scikit-learn \
    filelock \
    huggingface_hub \
    transformers \
    sentencepiece \
    tokenizers

# ---- Download model at build time so no internet needed at runtime ----
ENV TRANSFORMERS_CACHE=/ezr/model_cache
RUN python3.7 -c "\
from transformers import AutoTokenizer, AutoModel; \
m = 'sentence-transformers/all-MiniLM-L6-v2'; \
AutoTokenizer.from_pretrained(m, cache_dir='/ezr/model_cache'); \
AutoModel.from_pretrained(m, cache_dir='/ezr/model_cache'); \
print('Model downloaded and cached.')"

# ---- AFL++ env vars ----
ENV AFL_MAP_SIZE=256000
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_NO_AFFINITY=1
ENV AFL_DRIVER_DONT_DEFER=1
ENV AFL_NO_UI=1

# ---- Copy fuzzer ----
WORKDIR /ezr
COPY ezr_magma_fuzzer.py .

ENTRYPOINT ["python3.7", "/ezr/ezr_magma_fuzzer.py"]
CMD ["--target", "libpng", "--duration", "3600"]
DOCKERFILE

docker build -f Dockerfile.ezr -t ezr_fuzzer .
echo "✓ EZR Fuzzer image built"

# -----------------------------------------------------------------------
# Step 3: Create run script
# -----------------------------------------------------------------------
cat > run_ezr.sh << 'RUNEOF'
#!/bin/bash
TARGET=${1:-libpng}
DURATION=${2:-3600}
RESULTS_DIR="$(pwd)/ezr_results"
mkdir -p "$RESULTS_DIR"

echo "Starting EZR Fuzzer"
echo "  Target   : $TARGET"
echo "  Duration : ${DURATION}s"
echo "  Results  : $RESULTS_DIR"
echo ""

docker run -it --rm \
    --user root \
    --privileged \
    -v "$RESULTS_DIR":/ezr/work \
    ezr_fuzzer \
    --target "$TARGET" \
    --duration "$DURATION"
RUNEOF

chmod +x run_ezr.sh

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Run the fuzzer:"
echo "  ./run_ezr.sh libpng 3600"
echo ""
echo "Available targets: libpng, libtiff, libxml2, sqlite3"
echo ""