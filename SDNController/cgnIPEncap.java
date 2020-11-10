package net.floodlightcontroller.cgnipencap;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.List;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;

import org.projectfloodlight.openflow.protocol.OFFlowAdd;
//import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;


import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class cgnIPEncap implements IOFMessageListener, IFloodlightModule {

	public static int FLOWMOD_DEFAULT_IDLE_TIMEOUT = 5; // in seconds
    public static int FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
    public static int FLOWMOD_DEFAULT_PRIORITY = 1;
	
	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
		
	protected String targetSrcIP = "192.168.1.201";
	protected String targetDstIP = "192.168.1.202";
	
	protected int pcount = 0;
	
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return cgnIPEncap.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =
		        new ArrayList<Class<? extends IFloodlightService>>();
		    l.add(IFloodlightProviderService.class);
		return l;
		
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	    macAddresses = new ConcurrentSkipListSet<Long>();
	    logger = LoggerFactory.getLogger(cgnIPEncap.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		
		Ethernet eth =
                IFloodlightProviderService.bcStore.get(cntx,
                                            IFloodlightProviderService.CONTEXT_PI_PAYLOAD);						
		
		if (eth.getEtherType() != EthType.IPv4) {
			OFMessage outMessage;
			outMessage = createHubPacketOut(sw, msg);
			sw.write(outMessage);
			return Command.CONTINUE;
		}
		
		IPv4 ipv4 = (IPv4) eth.getPayload();		

		if (! (targetSrcIP.equals(ipv4.getSourceAddress().toString()) && targetDstIP.equals(ipv4.getDestinationAddress().toString()))) {
			OFMessage outMessage;
			outMessage = createHubPacketOut(sw, msg);
			sw.write(outMessage);
			return Command.CONTINUE;
		}
		
		logger.info("Received our target IP packet. Turn it to IP-in-IP packet!!");		
		
		// Generate serialized ipip packet
		byte[] ipip = getIPIP(eth, ipv4);
		
		
		// Create PACKET_OUT message
		logger.info("length of sent out data: " + ipip.length);		// 
		OFPacketIn pi = (OFPacketIn) msg;
		OFPacketOut po = sw.getOFFactory().buildPacketOut() /* mySwitch is some IOFSwitch object */
			    .setData(ipip)
			    .setXid(pi.getXid())
			    .setInPort((pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT)))
			    .setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().output(OFPort.FLOOD, 0xffFFffFF)))    
			    .build();		
		
		sw.write(po);
		
		logger.info("IP-in-IP packet is sent out!");
		
		
		return Command.CONTINUE;
		
	}	
	
	public byte[] getIPIP(Ethernet eth, IPv4 innerIP) {		
		
		IPv4 ipip = (IPv4) innerIP.clone();
				
		// Inner IP: add options
		byte[] option = getOption(innerIP.getDestinationAddress()); 
		logger.info("Options is: " + option);
		logger.info("Length of options: " + option.length);
		innerIP.setOptions(option); // Total length and header length is reset when we call serialize function.		
		innerIP.resetChecksum(); // Reset checksum
		
		ipip.setPayload(innerIP);
		
		// Set IPIP protocol type
		ipip.setProtocol(IpProtocol.IPv4);
		
		logger.info("Trying to serialize ipip packet");
		ipip.resetChecksum();
		
		logger.info("Total length of IPIP packet: " + ipip.getTotalLength()); // Cannot set length
		logger.info("Header length of IPIP packet: " + ipip.getHeaderLength()); // Cannot set length			
		
		eth.setPayload(ipip);
		eth.resetChecksum();
		return eth.serialize();
	}
		
	
	byte[] getOption(IPv4Address dstIP) {
			
		byte[] cookie = getCookies(dstIP);
		int hex1 = 0xde; // Type of experiment
		int hex2 = 0x28; // Length of option is 40				
		// option = hex1 + hex2 + option;
		byte[] option = ByteBuffer
				.allocate(40)
				.put((byte)hex1).put((byte)hex2).put(cookie)
				.array();
		
		if (option.length != 40) {
			System.out.println("Length of options is not 40!!");
		}
		return option;
	}
	
	// Generate cookies
	byte[] getCookies(IPv4Address dstIP) {		
		String clientKey = getClientKey(); // length: 10
		String uid = getUID(); // Length: 5
		String nonce1 = "12"; // length: 2		
		String nonce2 = generateNonce(); // length: 2
		String input = uid + nonce2 + clientKey;
		String hashtext; // Length: 28
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-224");
			byte[] messageDigest = md.digest(input.getBytes());
			BigInteger no = new BigInteger(1, messageDigest);
			hashtext = no.toString(16);
			// Mark here
			// Sometimes it could be length of odd number, then we need to pad it
			if (hashtext.length() != 56) {
				logger.info("Length of hexdump of hashtext is not 56");
				hashtext = "0" + hashtext;
			}
			logger.info("Bytes in hex string: " + hashtext);
		} 
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}				
		
		logger.info("Cookie in bytes: " + hexStringToByteArray(hashtext));
		logger.info("Length of hash in bytes: " + hexStringToByteArray(hashtext).length); // 28 is good
				
		
		byte[] result = ByteBuffer
				.allocate(38)
				.put("1".getBytes()).put(uid.getBytes()).put(nonce1.getBytes()).put(nonce2.getBytes()).put(hexStringToByteArray(hashtext))
				.array();
		
		logger.info("Length of result: " + result.length);

		return result;
	}
	
	String getClientKey() {
		return "cc5734c9c834e5d879bee2714868a2448d7778c9cd574f483b155dc5";
	}
	
	String getUID() {
		return "12345";
	}
	
	String generateNonce() {
		return "34";
	}
	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	private OFMessage createHubPacketOut(IOFSwitch sw, OFMessage msg) {
		OFPacketIn pi = (OFPacketIn) msg;
	    OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
	    pob.setBufferId(pi.getBufferId()).setXid(pi.getXid()).setInPort((pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT)));
	    
	    // set actions
	    OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
	    actionBuilder.setPort(OFPort.NORMAL);
	    pob.setActions(Collections.singletonList((OFAction) actionBuilder.build()));
	
	    // set data if it is included in the packetin
	    if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
	        byte[] packetData = pi.getData();
	        pob.setData(packetData);
	    }
	    return pob.build();  
	}
}
