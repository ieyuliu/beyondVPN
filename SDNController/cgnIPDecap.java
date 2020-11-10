package net.floodlightcontroller.cgnipdecap;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Arrays;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.python.constantine.platform.darwin.IPProto;

import net.floodlightcontroller.cgnipencap.cgnIPEncap;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;


import net.floodlightcontroller.core.IFloodlightProviderService;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Set;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.PacketParsingException;
import net.floodlightcontroller.packet.TCP;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class cgnIPDecap implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;	
	protected static Logger logger;
	
	// Response packets
	// Value of the IP addresses should be dynamic
	protected String serverIP = "192.168.1.202";
	protected String clientIP = "192.168.1.201";
	
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return cgnIPDecap.class.getSimpleName();
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
	    logger = LoggerFactory.getLogger(cgnIPDecap.class);
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
				
//		*********************************************************Controller as Hub*************************************************************** 		
//		logger.info("Received packet and sent out");
//		OFMessage outMessage2;
//		outMessage2 = createHubPacketOut(sw, msg);
//		sw.write(outMessage2);
//		return Command.CONTINUE;		
//		*****************************************************************************************************************************************

		
		if (clientIP.equals(ipv4.getSourceAddress().toString()) && serverIP.equals(ipv4.getDestinationAddress().toString())) {
			// Client => Server
			// Encapsulate the packet to indicate support
			
			IPv4 innerIP =  (IPv4) ipv4.clone();									
			
			// 0x33 = '3'
			byte[] options = ByteBuffer
					.allocate(4)
					.put((byte)0xde).put((byte)0x28).put((byte)0x33).put((byte)0x00)
					.array();
			innerIP.setOptions(options);
			innerIP.resetChecksum();
			ipv4.setProtocol(IpProtocol.IPv4);
			ipv4.setPayload(innerIP);
			ipv4.resetChecksum();
			eth.setPayload(ipv4);
			
			logger.info("Encapsulated the packet indicates protocol support");
			OFPacketIn pi = (OFPacketIn) msg;
			OFPacketOut po = sw.getOFFactory().buildPacketOut() /* mySwitch is some IOFSwitch object */
				    .setData(eth.serialize())
				    .setXid(pi.getXid())
				    .setInPort((pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT)))
				    .setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().output(OFPort.FLOOD, 0xffFFffFF)))    
				    .build();
			
			sw.write(po);
			logger.info("Encapsulated packet sent out");
			
			return Command.CONTINUE;
			
		}
		else if (serverIP.equals(ipv4.getSourceAddress().toString()) && clientIP.equals(ipv4.getDestinationAddress().toString())) {
			// Server => Client
			// Check if the packet is IP-in-IP
			if (ipv4.getProtocol() != IpProtocol.IPv4) {
				logger.info("cgnIPDecap: Not IP-in-IP packet, let it go");
				OFMessage outMessage;
				outMessage = createHubPacketOut(sw, msg);
				sw.write(outMessage);
				return Command.CONTINUE;
			}
			
			logger.info("cgnIPDecap: Received target IP-in-IP packet");			
			
			
			TCP tcpp = new TCP();
					
			byte[] tcpBytes = Arrays.copyOfRange(ipv4.serialize(), 80, 120);		
			// logger.info("TCP hex: " + bytesToHex(tcpBytes));
			
			try {
				tcpp.deserialize(tcpBytes, 0, 40);
			} catch (PacketParsingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();			
			}
			tcpp.resetChecksum();
			logger.info("TCP deserialized successfully");
			logger.info("TCP dst port: " + tcpp.getDestinationPort());
			
			ipv4.setPayload(tcpp);
			ipv4.setProtocol(IpProtocol.TCP);
			ipv4.resetChecksum();
			
			eth.setPayload(ipv4);
			 
			OFPacketIn pi = (OFPacketIn) msg;
			OFPacketOut po = sw.getOFFactory().buildPacketOut() /* mySwitch is some IOFSwitch object */
				    .setData(eth.serialize())
				    .setXid(pi.getXid())
				    .setInPort((pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT)))
				    .setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().output(OFPort.FLOOD, 0xffFFffFF)))    
				    .build();
			
			sw.write(po);
					
							
			logger.info("cgnIPDecap: decapsulated and sent packet out");
			OFMessage outMessage;
			outMessage = createHubPacketOut(sw, msg);
			sw.write(outMessage);
			return Command.CONTINUE;
		}
		else {
			// Send PACKET_OUT			
			OFMessage outMessage;
			outMessage = createHubPacketOut(sw, msg);
			sw.write(outMessage);
			return Command.CONTINUE;
		}
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

	
	private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for (int j = 0; j < bytes.length; j++) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
	        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
	    }
	    return new String(hexChars);
	}

	
	private void parseOptions(byte[] options) {
		logger.info("cgnIPDecap: Parsing inner IP options.");
		// Get the
		String strOptions = options.toString();
		if (strOptions.length() < 40) {
			logger.info("cgnIPDecap: Length of options is less than 40 bytes, return");
			return;
		}
		// Uid: 5, nonce1:2, SSH224: 28
		String uid = strOptions.substring(3, 8);
		String nonce1 = strOptions.substring(8, 10);
		String clientKeySSH224 = strOptions.substring(10, 38);
		BigInteger no = new BigInteger(1, clientKeySSH224.getBytes());
		String clientKeyHex = no.toString(16);
		
		logger.info("cgnIPDecap: Uid: " + uid);
		logger.info("cgnIPDecap: Nonce1: " + nonce1);
		logger.info("cgnIPDecap: clientKeyHex: " + clientKeyHex);
		logger.info("cgnIPDecap: Key information is stored on controller");
	}
	
}
