// @author: ucla-cs


import java.applet.*;
import javax.swing.*;
import netscape.javascript.*;

import java.lang.reflect.InvocationTargetException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Set;
import java.util.Timer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.io.*;



public class JavaSocketBridge extends JApplet {

	static String protocol = "TCP";

	static volatile Hashtable<String, SocketChannel> connections = new Hashtable<String, SocketChannel>();



	volatile String result = "";

	//static ConcurrentHashMap hm = null;
	static boolean isBrowser = true;




	private final static int PACKETSIZE = 2000 ;
	// Instance variables
	static JSObject browser = null;		// The browser

	protected Selector _ncReadSelector = null;
	protected Selector _ncWriteSelector = null;		


	// Initialize automatically called by browser
	public void init(){

		try{
			browser = JSObject.getWindow(this);
		}
		catch(Exception e){
			error( "ERROR IN INIT" + e.toString());
		}
	}

	//start automatically called by browser
	public void start(){
		try {
			browser.call("java_socket_bridge_ready", null);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			error("ERROR IN START" +e.toString());
		}

	}

	public String getOLD(final String h, final int p, final String interest, final int timeout){
		return AccessController.doPrivileged(
				new PrivilegedAction<String>() {
					public String run() {

						Socket sock=null;
						OutputStream out=null;
						InputStream in=null;

						try{	


							sock=new Socket(h,p);


							String word= interest;


							in = sock.getInputStream();

							out=sock.getOutputStream();


							System.out.println("Your string is"+word);

							out.write(hex2Bytes(word));
							out.flush();
							sock.shutdownOutput();

							ByteArrayOutputStream serverinput=new ByteArrayOutputStream();

							int len=0;
							byte[] buf=new byte[PACKETSIZE];
							while ((len = in.read(buf))>=0) {
								serverinput.write(buf, 0, len);
							}

							String outputString = bytes2Hex(buf);

							System.out.println("Your string is "+word+" converted to byte "+outputString);

							return outputString;

						} catch (Exception e) {
							// TODO Auto-generated catch block
							error(e);
						}


						finally{

							try {
								sock.close();
							} catch (IOException e) {
								// TODO Auto-generated catch block
								error(e);
							}

						}

						return "ERROR";
					}
				}

				);
	}

	public String get(final String h, final int p, final String interest,final int timeout){
		return AccessController.doPrivileged(
				new PrivilegedAction<String>() {
					public String run() {
						Thread t = new Thread( new Runnable(){
							public void run(){

								SocketChannel sChannelCloser = null;
								try{	

									final SocketChannel sChannel = open(h,p);

									sChannelCloser=sChannel;

									sChannel.socket().setSoTimeout(timeout);

									ByteBuffer buffer = ByteBuffer.wrap(hex2Bytes(interest));

									System.out.println("WRITING  BYTES:"+interest);

									while(buffer.hasRemaining())  
										sChannel.write(buffer);

									ByteBuffer bufferReceiver = ByteBuffer.allocate(PACKETSIZE);

									buffer.clear();  
									sChannel.read(bufferReceiver);

									String output =  bytes2Hex(bufferReceiver.array());
									System.out.println("RECEIVED BYTES:" +output);

									result=output;

									return ;

								} catch (Exception e) {
									// TODO Auto-generated catch block
									error(e);
								}
								finally{

									try {
										sChannelCloser.close();
									} catch (IOException e) {
										// TODO Auto-generated catch block
										error(e);
									}

								}



								//return "STARTED GETTING";

							}
						}

								);

						t.start();

						Long start = System.currentTimeMillis();
						Long current = System.currentTimeMillis();

						while(t.isAlive() && current-start < timeout ){
							try {
								Thread.sleep(100);
							} catch (InterruptedException e) {
								error(e);
							}
							current = System.currentTimeMillis();
						}
						if(current-start >= timeout){
							t.stop();
							return "TIMEOUT EXPIRED";
						}
						else{
							return result;

						}


					}
				}

				);
	}


	// Report an error
	public static void receivedInterest( String data,String name){

		Object[] arguments = new Object[2];
		arguments[0] = data;
		arguments[1] = name;


		try {
			browser.call("on_socket_received_interest", arguments);
		} catch (JSException e) {
			// TODO Auto-generated catch block
			error(e.getMessage());
		}

	}

	public String put(final String h, final int p, final String interest,final String name, final String toReturn){
		return AccessController.doPrivileged(
				new PrivilegedAction<String>() {
					public String run() {


						SocketChannel sChannelCloser = null;
						try{	

							final SocketChannel sChannel = open(h,p);
							sChannelCloser=sChannel;

							//FIRST TIME
							//ByteBuffer buffer = ByteBuffer.allocateDirect(1024);

							ByteBuffer buffer = ByteBuffer.wrap(hex2Bytes(interest));

							System.out.println("WRITING  BYTES:"+interest);
							while(buffer.hasRemaining())  
								sChannel.write(buffer);

							ByteBuffer bufferReceiver = ByteBuffer.allocate(PACKETSIZE);

							buffer.clear();  
							sChannel.read(bufferReceiver);

							System.out.println("RECEIVED BYTES:" + bytes2Hex(bufferReceiver.array()));




							Thread t = new Thread( new Runnable(){
								public void run(){
									//sChannel.
									while(true){

										try{

											ByteBuffer bufferReceiver = ByteBuffer.allocate(PACKETSIZE);

											bufferReceiver.clear();  
											sChannel.read(bufferReceiver);

											String receivedHexBytes = bytes2Hex(bufferReceiver.array());
											
											System.out.println("RECEIVED BYTES:" + receivedHexBytes);


											System.out.println("name is "+name);

											//connections.put(name, sChannel);

											//System.out.println("name is "+name);

											//receivedInterest(receivedHexBytes,name);


											//byte[] output = hex2Bytes("048202aa03b208855dea25cca4d3967c774cc6e709a140d91f9d74e97a665cbb106568ee94f998d8b22fbe2b8d2fc43bd9363b501a50f2d770a7882aaf0792c20359f54da27d4a5b5a29be7d349c656e60fd37c92cf4e4aae256af04161e561aa4323512b38799c43d7a2ec4e35c3e19599b12c5ee3a5f0994837461c05c294a8b596f960e9287520000f2faad726f63636f000001a203e2028548398bad0eeb58e9cc64720e84f4947fe1c1eb310055181ed0b4c2d920ef6e590002bab504fcc5336e9c0001e201da0a9530819f300d06092a864886f70d010101050003818d003081890281810092e67426906bae66a3f4910bade5a2d24e2b7ed0d7a3e16f368c258e848f30115f6e95f5e0ee64505ed3da08be6ee599d395f611ffb096a9c258171518f0c6b3612a94681d29e44619227ac268e5d450abac89820d96188f507d15fb40d8780ccb76a012f7ce4f4efe2b8ba431ef993e31da867adffb069003808bceef9ff4d10203010001000000019abd424f4e4a4f55520000"); 

											byte[] output = hex2Bytes(toReturn); 


											ByteBuffer outputBuffer = ByteBuffer.wrap(output);

											//byte[] output = hex2Bytes("048202aa03b208857d7f003e50fc79aca1563842832db26c5e313bec0940ce795dd8adc34e7fd2cadee7b44b28737d59c061240da60d0733e2bcc760c7656a0f03b20a987c1a1fb94bb93648243c48fde222bc21b85062f186ffdc15f637cfe83f35ab11e3564e7e83a26de39a0faf3991f469f0f376fca535fb1be28ede72b433547b4977f0f3000000f2faa574657374000001a203e20285189f9df9814d134883758f9c5541ba957a4464d8756f34870cf981143f56779a0002bab504fcbf24f6f60001e201da0a9530819f300d06092a864886f70d010101050003818d0030818902818100c0a2c68770c339ed3152b90cde701ba588652f358854460b36b866c6e76272013232df351f10841ac49e35a6bc644f9c9caacd9aa0cd0e1835a34162c9208049d3f1f893d0b9566854133a763756df45297328d595ba6b6459fd311d5e1c97ce5278fa076dde765090c7221670ad54689958cc5fb46699482c5ac16c301dba1f0203010001000000019abd424f4e4a4f55520000"); 

											while(outputBuffer.hasRemaining())  
												sChannel.write(outputBuffer);

											System.out.println("SENT BACK SOME DATA");


										}
										catch(Exception e){
											error(e);
											try {
												sChannel.close();
											} catch (IOException e1) {
												// TODO Auto-generated catch block
												error(e1);
											}
											System.exit(0);

										}
									}

								}});

							t.start();

							return "STARTED PUBLISHING";

							//return receivedHexBytes;

						} catch (Exception e) {
							// TODO Auto-generated catch block
							error(e);

							try {
								System.out.println("CLOSING THE CONNECTION");
								sChannelCloser.close();
							} catch (IOException ex) {
								// TODO Auto-generated catch block
								error(ex);

							}
						}
						return "FAILURE";



					}
				}
				);
	}



	public String putAnswer(final String s, final String dataBack){

		final SocketChannel sChannel = connections.get(s);


		byte[] output = hex2Bytes(dataBack);

		ByteBuffer outputBuffer = ByteBuffer.wrap(output);

		//byte[] output = hex2Bytes("048202aa03b208857d7f003e50fc79aca1563842832db26c5e313bec0940ce795dd8adc34e7fd2cadee7b44b28737d59c061240da60d0733e2bcc760c7656a0f03b20a987c1a1fb94bb93648243c48fde222bc21b85062f186ffdc15f637cfe83f35ab11e3564e7e83a26de39a0faf3991f469f0f376fca535fb1be28ede72b433547b4977f0f3000000f2faa574657374000001a203e20285189f9df9814d134883758f9c5541ba957a4464d8756f34870cf981143f56779a0002bab504fcbf24f6f60001e201da0a9530819f300d06092a864886f70d010101050003818d0030818902818100c0a2c68770c339ed3152b90cde701ba588652f358854460b36b866c6e76272013232df351f10841ac49e35a6bc644f9c9caacd9aa0cd0e1835a34162c9208049d3f1f893d0b9566854133a763756df45297328d595ba6b6459fd311d5e1c97ce5278fa076dde765090c7221670ad54689958cc5fb46699482c5ac16c301dba1f0203010001000000019abd424f4e4a4f55520000"); 



		try{
			while(outputBuffer.hasRemaining())  
				sChannel.write(outputBuffer);


			ByteBuffer bufferReceiver = ByteBuffer.allocate(PACKETSIZE);

			bufferReceiver.clear();  
			sChannel.read(bufferReceiver);

			String receivedHexBytes = bytes2Hex(bufferReceiver.array());
			System.out.println("RECEIVED BYTES:" + receivedHexBytes);


			receivedInterest(receivedHexBytes,s);

		}
		catch (Exception e) {
			// TODO Auto-generated catch block
			error(e);

			try {
				System.out.println("CLOSING THE CONNECTION");
				sChannel.close();
			} catch (IOException ex) {
				// TODO Auto-generated catch block
				error(ex);
				return "FAILURE";
			}
		}

		return "SUCCESS";

	}


	public SocketChannel open(String host, int ip) throws IOException{
		// Create a non-blocking socket channel
		SocketChannel sChannel = SocketChannel.open();

		//sChannel.configureBlocking(false);

		// Send a connection request to the server; this method is non-blocking
		sChannel.connect(new InetSocketAddress(host, ip));

		// Before the socket is usable, the connection must be completed
		// by calling finishConnect(), which is non-blocking

		_ncReadSelector = Selector.open();
		//sChannel.configureBlocking(false);
		//sChannel.register(_ncReadSelector, SelectionKey.OP_READ);
		_ncWriteSelector = Selector.open();
		//sChannel.register(_ncWriteSelector, SelectionKey.OP_WRITE);


		while (!sChannel.finishConnect()) {
			// Do something else
			System.out.println("TRYING TO CONNECT");
		}
		System.out.println("CONNECTED TO " +host +":"+ip);

		return sChannel;
	}


	public static void error(Exception ex){
		StringWriter sw = new StringWriter();
		ex.printStackTrace(new PrintWriter(sw));
		String exceptionAsStrting = sw.toString();

		error(exceptionAsStrting );
	}
	// Report an error
	public static void error(String message){

		System.out.println("RECEIVED AN ERROR");
		message = "Java Socket Bridge ERROR: " + message;
		Object[] arguments = new Object[1];
		arguments[0] = message;

		if(isBrowser){
			try {
				browser.call("on_socket_error", arguments);
			} catch (JSException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else{
			System.out.println(message);
		}
	}




	// Log something
	public void log(String message){
		System.out.println(message);
	}


	public static byte[] hex2Bytes(String str)
	{
		byte[] bytes = new byte[str.length() / 2];
		for (int i = 0; i < bytes.length; i++)
		{
			bytes[i] = (byte) Integer
					.parseInt(str.substring(2 * i, 2 * i + 2), 16);
		}

		return bytes;
	}
	public static String bytes2Hex(byte[] b)
	{
		// String Buffer can be used instead
		String hs = "";
		String stmp = "";

		for (int n = 0; n < b.length; n++)
		{
			stmp = (java.lang.Integer.toHexString(b[n] & 0XFF));

			if (stmp.length() == 1)
			{
				hs = hs + "0" + stmp;
			}
			else
			{
				hs = hs + stmp;
			}

			if (n < b.length - 1)
			{
				hs = hs + "";
			}
		}

		return hs;
	}


	public static void main(String[] args) throws IOException {

		JavaSocketBridge b = new JavaSocketBridge();

		//System.out.println( b.get("127.0.0.1",9695 ,"01D2F2FAA4657374000000", 1000));

		//System.out.println( b.get("127.0.0.1",9695 ,"01D2F2FAA574657374000000", 1000));

		//System.out.println( b.putSend("127.0.0.1",9695 ,"01d2f2faa563636e7800fa0285e0a01e093968f9740ce7f4361babf5bb05a4e55aaca5e58f73eddeb8e013aa8f00fabd73656c6672656700fa1bf5048202aa03b2088568cf069cdfdedad97ad9358f7e2446ca581eaa22ed9eb4e482fe616b35840533ba4f9d321155d6c34915dff7352de5e60bddb17e32f893cd89056cfd291011a5c3742312a083c2628fed4ddffb04cf51e6860eb1dbd43ff9b59736e62ec1a69218ce0acfdd9da896a617f609c12225f14a63876488b38d3a7b9fc1757d9058470000f20001a203e2028547ab87ece0e191c5e946f839507bc875c63c7032e42c347c135a952e7187c9300002bab504fcb2a6a0250001e201da0a9530819f300d06092a864886f70d010101050003818d003081890281810089b8f8b42d8aa31148d9f2a0c38d3fee7c73f60ea444d08fd886114a689cfe235c49bf9e256489390c19d961aabd5ee6d9e9e133282cd68b046609fe0a81be76c683cb150f3d035231b25745530fc887fbd137d6ef9c05d795fdb78f84eeab6f7dcbd1aa64b3920d96cfe941b66967bb2892baef1995bea231a4dc89c383e8550203010001000000019a0585058a04cabe73656c6672656700f2faad726f63636f000003e20285e0a01e093968f9740ce7f4361babf5bb05a4e55aaca5e58f73eddeb8e013aa8f0004fa8e330003d2d63231343734383336343700000000000002d28e310000",1000));

		//System.out.println( b.putSend("127.0.0.1",9695 ,"01D2F2FAA574657374000000",1000));


		//System.out.println( b.getSend("127.0.0.1",9695 ,"01D2F2FAA574657374000000", 1000));

		//System.out.println( b.get("localhost",9695 ,"01d2f2fafd",3000));

		//System.out.println( b.get("localhost",9695 ,"01D2F2FAA574657374000",3000));


		//System.out.println( b.getOLD("localhost",9695 ,"01d2f2fafdc12e4d2e532e6c6f63616c686f737400fabdc12e4d2e53525600faa563636e6400fa9d4b4559000002d28e310000",1000));


		//System.out.println( b.putSend("localhost",9695 ,"01d2f2faa563636e7800fa0285e0a01e093968f9740ce7f4361babf5bb05a4e55aaca5e58f73eddeb8e013aa8f00fabd73656c6672656700fa1bf5048202aa03b208854a18988c72aee624da28e2e1acbccb209b8e89429041985521ed68f95a1c546872fba3d854b1377dc249b6d8ec5935e5069256c97a7f6d8a62e86222ccd2cfe5097aed3fe5ede6732ce191a8680d78e39d0c5058a2b7bb0f0687994e9f045de346b66c46498547a08da1f2f0cdfafba3afdfe7107931935ede79040137ba94a90000f20001a203e202851a4860caa4991e829bcdc9429fb711d52440968d23560726606050bf147acffc0002bab504fcb3f03aa40001e201da0a9530819f300d06092a864886f70d010101050003818d00308189028181008ed27580e3d1c4c67672208665133a1ba12d8ebf5cad8e054571926b3ff0782a04c71703384021a6cefb6616b66cbd8a679b761d69d6373a851546e26f7105510b4c23be9a3c7f2e652e100ecc1471855730659f1477ce4e8504ad1fd8f44116baaeae2ff67eec33abba790157a79bf5039e5a528a471d9d67c94e70117ed7490203010001000000019a0585058a04cabe73656c6672656700f2faad726f63636f000003e20285e0a01e093968f9740ce7f4361babf5bb05a4e55aaca5e58f73eddeb8e013aa8f0004fa8e330003d2d63231343734383336343700000000000002d28e310000", 1000));

		//b.putSend("localhost",9695 ,"01d2f2faa563636e7800fa0285e0a01e093968f9740ce7f4361babf5bb05a4e55aaca5e58f73eddeb8e013aa8f00fabd73656c6672656700fa1bf5048202aa03b208854a18988c72aee624da28e2e1acbccb209b8e89429041985521ed68f95a1c546872fba3d854b1377dc249b6d8ec5935e5069256c97a7f6d8a62e86222ccd2cfe5097aed3fe5ede6732ce191a8680d78e39d0c5058a2b7bb0f0687994e9f045de346b66c46498547a08da1f2f0cdfafba3afdfe7107931935ede79040137ba94a90000f20001a203e202851a4860caa4991e829bcdc9429fb711d52440968d23560726606050bf147acffc0002bab504fcb3f03aa40001e201da0a9530819f300d06092a864886f70d010101050003818d00308189028181008ed27580e3d1c4c67672208665133a1ba12d8ebf5cad8e054571926b3ff0782a04c71703384021a6cefb6616b66cbd8a679b761d69d6373a851546e26f7105510b4c23be9a3c7f2e652e100ecc1471855730659f1477ce4e8504ad1fd8f44116baaeae2ff67eec33abba790157a79bf5039e5a528a471d9d67c94e70117ed7490203010001000000019a0585058a04cabe73656c6672656700f2faad726f63636f000003e20285e0a01e093968f9740ce7f4361babf5bb05a4e55aaca5e58f73eddeb8e013aa8f0004fa8e330003d2d63231343734383336343700000000000002d28e310000", 1000);

		//NewTest(54567);

		//System.out.println( b.put());

		//connections.put("meki", SocketChannel.open());

	}

}