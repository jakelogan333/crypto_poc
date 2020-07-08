rmdir /Q /S build
mkdir build
cd build

cmake -G Ninja ..

Ninja

cd ..
REM build\crypto.exe