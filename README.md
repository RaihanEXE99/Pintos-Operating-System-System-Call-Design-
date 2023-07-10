# Install Process
cd to threads folder then,
make threads

cd to examples folder then,
make examples 

cd to userprog folder then,
make userprog 

cd userprog/build
pintos-mkdisk filesys.dsk --filesys-size=2

cd to utils folder then,
make utils