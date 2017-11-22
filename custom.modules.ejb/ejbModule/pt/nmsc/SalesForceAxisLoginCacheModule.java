/**
 * Custom SAP PI adapter module to make the Lookup 
 * to get the token (SessionID) and Dynamic TargetURL from Salesforce
 *
 * @author  Nuno Correia
 * @version 1.1
 * @since   2016-11-27 
 */

package pt.nmsc;

//Classes for EJB and XML parsing
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Calendar;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
//import javax.ejb.Local;
//import javax.ejb.LocalHome;
//import javax.ejb.Remote;
//import javax.ejb.RemoteHome;
//import javax.ejb.Stateless;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
//Add SAP_XIAF SC DC's to adapter EJB DC, as it contains the needed dependencies
import javax.xml.rpc.handler.soap.SOAPMessageContext;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

//Classes for SAP adapter development and mapping - SOAP lookup
//Build Path Libraries
import com.sap.aii.af.lib.mp.module.Module;
import com.sap.aii.af.lib.mp.module.ModuleContext;
import com.sap.aii.af.lib.mp.module.ModuleData;
import com.sap.aii.af.lib.mp.module.ModuleException;
//import com.sap.aii.af.lib.mp.module.ModuleHome;
//import com.sap.aii.af.lib.mp.module.ModuleLocal;
//import com.sap.aii.af.lib.mp.module.ModuleLocalHome;
//import com.sap.aii.af.lib.mp.module.ModuleRemote;
import com.sap.aii.mapping.lookup.Channel;
import com.sap.aii.mapping.lookup.LookupService;
import com.sap.aii.mapping.lookup.Payload;
import com.sap.aii.mapping.lookup.SystemAccessor;
import com.sap.engine.interfaces.messaging.api.MessageKey;
import com.sap.engine.interfaces.messaging.api.PublicAPIAccessFactory;
import com.sap.engine.interfaces.messaging.api.auditlog.AuditAccess;
import com.sap.engine.interfaces.messaging.api.auditlog.AuditLogStatus;

//Classes for Java DB Lookup
import pt.nmsc.jpa.SFLoginBeanLocal;
import pt.nmsc.jpa.SFLoginEntity;

/**
* Session Bean implementation class SalesForceAxisLoginCacheModule
*/
// Info in descriptor ejb-jar.xml
//@Stateless(name = "SalesForceAxisLoginCacheModule")
//@Local(value = {ModuleLocal.class})
//@Remote(value = {ModuleRemote.class})
//@LocalHome(value = ModuleLocalHome.class)
//@RemoteHome(value = ModuleHome.class)
public class SalesForceAxisLoginCacheModule implements Module {

	// Axis properties
	private static final String MESSAGE_KEY_PROP 	= "message.key";
	private static final String URL_PROP 			= "transport.url";
	// External parameters
	private static final String USER_PARM 			= "username";
	private static final String PWD_PARM 			= "pwd";
	private static final String SERVICE_PARAM		= "service";
	private static final String CHANNEL_PARAM		= "channel";
	private static final String FIXED_PATH			= "fixedPath";

	// Audit and message key objects for logging
	private AuditAccess audit;
	private MessageKey mk;
	
	// PI JAVA DB handler bean injection
	@EJB(beanInterface=SFLoginBeanLocal.class)
	private SFLoginBeanLocal sfdb;


	@PostConstruct
	public void initializeResources() {
		try {
			this.audit = PublicAPIAccessFactory
				.getPublicAPIAccess().getAuditAccess();
		} catch(Exception e) {
			throw new RuntimeException(
					"Error in initialiseResources():" + e.getMessage());
		}
	}

	@Override
	public ModuleData process(ModuleContext moduleContext,
			ModuleData inputModuleData) throws ModuleException {

		// SOAPMessageContext since is an Axis message type.
		// Cannot cast to Message...
		SOAPMessageContext msg =
			(SOAPMessageContext)inputModuleData.getPrincipalData();

		// Getting message key from Axis context
		this.mk = (MessageKey)msg.getProperty(MESSAGE_KEY_PROP);

		// Log
		this.audit.addAuditLogEntry(this.mk, AuditLogStatus.SUCCESS,
			"Enter: SalesForceAxisLoginCacheModule::process");

		// Getting module parameters
		String username = 	(String)moduleContext.getContextData(USER_PARM);
		String pwd 		= 	(String)moduleContext.getContextData(PWD_PARM);
		String service 	= 	(String)moduleContext.getContextData(SERVICE_PARAM);
		String channel 	= 	(String)moduleContext.getContextData(CHANNEL_PARAM);
		String fixedPath = 	(String)moduleContext.getContextData(FIXED_PATH);

		try {
			
			// ------------- CACHE SECTION ------------- 
			// Check Java cache Table for session token
			SFLoginEntity token = this.sfdb.getToken(username);
			
			// Local variables for output message
			String sessionID = null;
			String targetURL = null;

			Calendar currentTS = Calendar.getInstance();
			Calendar expireTS = Calendar.getInstance();
			SimpleDateFormat dateFormat =
				new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
			
			// Token exists
			if(token != null) {
				//Parse timestamp
				expireTS.setTime(dateFormat.parse(token.getVALIDITY()));

				// Token still valid
				if(expireTS.compareTo(currentTS) > 0) {
					sessionID = token.getSESSIONID();
					targetURL = token.getTARGETURL();
					
					this.audit.addAuditLogEntry(this.mk, AuditLogStatus.SUCCESS,
							"SessionID for " + username + " is still valid.");
				}
			}
			
			// Token expired or does not exists
			if(sessionID == null) {
				
				// Engage login, SOAP lookup
				String[] salesForceParams =
					this.getSessionIDSOAPLookup(username,pwd,
							service, channel, fixedPath);
				
				// Fill local data
				sessionID = salesForceParams[0];
				targetURL = salesForceParams[1];

				// New expire timestamp
				currentTS.add(Calendar.SECOND,
						      Integer.parseInt(salesForceParams[2]));
				
				// New token - create db reg
				if(token == null) {
					this.sfdb.addToken(username, salesForceParams[0],
							dateFormat.format(currentTS.getTime()), salesForceParams[1]);
					
					this.audit.addAuditLogEntry(this.mk, AuditLogStatus.SUCCESS,
							"SessionID for " + username + " does not exist.");
				}
				// SessionID expired
				else {
					this.sfdb.updateToken(username, salesForceParams[0],
							dateFormat.format(currentTS.getTime()), salesForceParams[1]);
					
					this.audit.addAuditLogEntry(this.mk, AuditLogStatus.SUCCESS,
							"SessionID for " + username + " expired.");
				}
			}
			// ------------- /CACHE SECTION -------------

			// ------------- OUTPUT AXIS MESSAGE SECTION -------------
			// Change axis message soap header to add the session id
			msg.getMessage().getSOAPHeader()
			.addNamespaceDeclaration("urn", "urn:enterprise.soap.sforce.com")
			.addChildElement("SessionHeader", "urn")
			.addChildElement("sessionId", "urn").setValue(sessionID);

			// Dynamic receiver URL
			msg.setProperty(URL_PROP, targetURL);

			this.audit.addAuditLogEntry(this.mk, AuditLogStatus.SUCCESS,
				"Exit: SalesForceAxisLoginCacheModule::process");
			// ------------- /OUTPUT AXIS MESSAGE SECTION -------------

		} catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}

		return inputModuleData;
	}

	/**
	 * Axis SOAP lookup given the communication channel and business component
	 * corresponding to a Salesforce system. Returns the session id and the URL
	 * used in future Salesforce operations.
	 *
	 * @param  username		user to login
	 * @param  pwd 			password to login
	 * @param  serviceName	business component
	 * @param  channelName	communication channel
	 * @param  fixedPath    URL fixed path
	 * @return result 		session id and target URL
	 */
	private String[] getSessionIDSOAPLookup(String username, String pwd,
									String serviceName, String channelName,
									String fixedPath) throws Exception {
		
		this.audit.addAuditLogEntry(this.mk, AuditLogStatus.SUCCESS,
			"Enter: SalesForceAxisLoginCacheModule::getSessionIDSOAPLookup");
		
		String sessionId = "";
		String targetUrl = "";
		String validity = "";

		Channel channel = LookupService.getChannel(serviceName, channelName);
		SystemAccessor accessor = LookupService.getSystemAccessor(channel);
		
		String loginxml = 	"<login xmlns=\"urn:enterprise.soap.sforce.com\">" +
								"<username>" + username + "</username>" +
								"<password>" + pwd		+ "</password>" +
							"</login>";

		InputStream inputStream = new ByteArrayInputStream(loginxml.getBytes());
		Payload payload = LookupService.getXmlPayload(inputStream);
		Payload SOAPOutPayload = null;
		SOAPOutPayload = accessor.call(payload);
		InputStream inp = SOAPOutPayload.getContent();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document document = builder.parse(inp);

		Node sessionNode =
			document.getElementsByTagName("sessionId").item(0);

		Node urlNode =
			document.getElementsByTagName("serverUrl").item(0);
		
		Node validityNode =
			document.getElementsByTagName("sessionSecondsValid").item(0);
		
		if (sessionNode != null) {
			sessionNode = sessionNode.getFirstChild();
			if (sessionNode != null) sessionId = sessionNode.getNodeValue();
		}

		if (urlNode != null) {
			urlNode = urlNode.getFirstChild();
			if (urlNode != null) {
				targetUrl = urlNode.getNodeValue();
				
				//If fixed path is defined, will replace the dynamic one
				if (fixedPath != null && !fixedPath.isEmpty() ) {
					URL dynURL = new URL(targetUrl);
					targetUrl = dynURL.getProtocol() + "://" + dynURL.getHost() + fixedPath;
				}
			}
		}
		
		if (validityNode != null) {
			validityNode = validityNode.getFirstChild();
			if (validityNode != null) validity = validityNode.getNodeValue();
		}

		String[] result = {sessionId, targetUrl, validity};
		
		this.audit.addAuditLogEntry(this.mk, AuditLogStatus.SUCCESS,
			"Exit: SalesForceAxisLoginCacheModule::getSessionIDSOAPLookup");
		
		return result;
	}

}