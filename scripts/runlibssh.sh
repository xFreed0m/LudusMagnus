curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get -y update
apt-cache policy docker-ce
sudo apt-get install -y docker-ce
sudo docker run -d -it -p 2222:22 --rm vulhub/libssh:0.8.1
echo $0  > flag6.txt
id=$(docker ps | awk '{print $1}' | tail -1)
docker cp flag6.txt $id:/flag6.txt
rm flag6.txt
