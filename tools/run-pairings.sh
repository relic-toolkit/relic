set -e

for script in preset/x64-pbc-*; do
 file=${script##*/}
 file=${file%.sh}
 echo target-$file
 mkdir -p target-$file
 cd target-$file
 ../$script ../
 make
 ./bin/test_fpx && ./bin/test_pc
 cd ..
done
