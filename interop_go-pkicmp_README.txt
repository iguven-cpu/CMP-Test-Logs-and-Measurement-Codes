To run go-pkicmp CMP Server.

1) sudo apt update
sudo apt install -y git golang openssl 
cd /opt
sudo git clone https://github.com/tsaarni/go-pkicmp.git
sudo chown -R $USER:$USER /opt/go-pkicmp
cd /opt/go-pkicmp
go mod download

2) Apply the changes for "main.go" and "algorithms.go" files check "interop_go-pkicmp_configuration_changes.txt"
3) Run "go run ./examples/mockserver/cmd" in "/opt/go-pkicmp" folder.
4) Wait to see like;
   2026/08/31 21:36:49 INFO CA ready subject="CN=Test CA" serial=177504611890161228825829411121010117247
   2026/08/31 21:36:49 INFO mockserver listening addr=192.168.7.77:6080 path=/cmp
5) Do not close this terminal tab so server is listening all the time.
6) Now you can send client CMP message to the Server like;
	/msps -cmd ir -server http://192.168.7.77:6080 -path cmp -ref msps -secret pass:SecretCmp -certout /****/****/****/referenceCert 
	-subject /CN=test-genCMPClientDemo/OU=For testing purposes only/O=Siemens/C=DE/OU=IDevID -newkey /****/****/****/newKeyGenRSA
7) For HTTPs server.key and server.crt should be created and used. It's configuration change is shown in "interop_go-pkicmp_configuration_changes.txt" file "C" section.


