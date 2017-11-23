package pt.nmsc;

//Classes for EJB and XML parsing
import javax.ejb.Local;
import javax.ejb.LocalHome;
import javax.ejb.Remote;
import javax.ejb.RemoteHome;
import javax.ejb.Stateless;
import javax.xml.bind.DatatypeConverter;
import javax.xml.namespace.QName;
import javax.xml.rpc.handler.soap.SOAPMessageContext;

// Certificate operations
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

// Axis libraries for parsing
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.message.MessageElement;

//Classes for SAP adapter module development
import com.sap.aii.af.lib.mp.module.Module;
import com.sap.aii.af.lib.mp.module.ModuleContext;
import com.sap.aii.af.lib.mp.module.ModuleData;
import com.sap.aii.af.lib.mp.module.ModuleException;
import com.sap.aii.af.lib.mp.module.ModuleHome;
import com.sap.aii.af.lib.mp.module.ModuleLocal;
import com.sap.aii.af.lib.mp.module.ModuleLocalHome;
import com.sap.aii.af.lib.mp.module.ModuleRemote;

import com.sap.aii.af.service.resource.SAPSecurityResources;
import com.sap.aii.security.lib.KeyStoreManager;
import com.sap.aii.security.lib.PermissionMode;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.BouncyCastle;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.EnvelopeIdResolver;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.PKIPathSecurity;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Session Bean implementation class WSAAndCertificateExtractorModule
 */
@Stateless(mappedName = "WSAAndCertificateExtractorModule")
@Local(value = {ModuleLocal.class})
@Remote(value = {ModuleRemote.class})
@LocalHome(value = ModuleLocalHome.class)
@RemoteHome(value = ModuleHome.class)
public class WSAAndCertificateExtractorModule implements Module {

	// Used namespaces
	private static final String NS_WSADDRESSING =
		"http://www.w3.org/2005/08/addressing";
	
	private static final String NS_WSSECURITY =
		"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

	// XML Tags (read)
	private static final String TAG_REPLYTO = "ReplyTo";
	private static final String TAG_ADDRESS = "Address";
	private static final String TAG_FAULTTO = "FaultTo";
	private static final String TAG_MSGID = "MessageID";
	private static final String TAG_SECURITY = "Security";
	private static final String TAG_SIGN = "Signature";
	private static final String TAG_SECTOKEN = "BinarySecurityToken";
	
	// XML Tags (write)
	private static final String TAG_CERTISSUER = "CertIssuer";
	private static final String TAG_CERTSUBJ = "CertSubject";


	@Override
	public ModuleData process(ModuleContext moduleContext,
			ModuleData inputModuleData) throws ModuleException {

		SOAPMessageContext msgContext =
			(SOAPMessageContext)inputModuleData.getPrincipalData();

		Message msg = ((MessageContext)msgContext).getCurrentMessage();

		try {

			// --- WSS Addressing
			MessageElement replyToElement = (MessageElement)msg.getSOAPHeader()
								.getElementsByTagNameNS(NS_WSADDRESSING, TAG_REPLYTO).item(0);
			
			MessageElement replyToAddressElement = null;
			if(replyToElement != null)
				replyToAddressElement = (MessageElement)replyToElement
								.getElementsByTagNameNS(NS_WSADDRESSING, TAG_ADDRESS).item(0);
			
			MessageElement faultToElement = (MessageElement)msg.getSOAPHeader()
								.getElementsByTagNameNS(NS_WSADDRESSING, TAG_FAULTTO).item(0);
			
			MessageElement faultToAddressElement = null;
			if(faultToElement != null)
				faultToAddressElement = (MessageElement)faultToElement
								.getElementsByTagNameNS(NS_WSADDRESSING, TAG_ADDRESS).item(0);
			
			MessageElement msgidElement = (MessageElement)msg.getSOAPHeader()
				.getElementsByTagNameNS(NS_WSADDRESSING, TAG_MSGID).item(0);

			
			// --- WSS Security Certificate - BinarySecurityToken
			MessageElement secElement = (MessageElement)msg.getSOAPHeader()
								.getElementsByTagNameNS(NS_WSSECURITY, TAG_SECURITY).item(0);
			
			X509Certificate cert = null;
			if(secElement != null) {
				
				MessageElement sigElement = (MessageElement)secElement
								.getElementsByTagName(TAG_SIGN).item(0);
				
				if(sigElement != null) {
					
					// Keystore
					SAPSecurityResources securityResources = SAPSecurityResources.getInstance();
				    KeyStoreManager keystoreManager = securityResources.getKeyStoreManager(PermissionMode.KEYSTORE,
						    new String[] { "CustomModules/NMSC/WSAAndCertificateExtractorModule" });
				    
				    // TODO module parameter
				    KeyStore keyStore = keystoreManager.getKeyStore("DEFAULT");
					if (keyStore == null)	throw new RuntimeException("Keystore not found.");
					
					// Get certificate from xml security token reference element
					//cert = this.getCertificate(sigElement, keyStore);

					MessageElement bstElement = (MessageElement)secElement
								.getElementsByTagName(TAG_SECTOKEN).item(0);
					
					if(bstElement != null) {
						String binarySecurityToken = bstElement.getValue();
						
						// Decode from base 64
						byte encodedCert[] = DatatypeConverter.parseBase64Binary(binarySecurityToken);
						ByteArrayInputStream isToken = new ByteArrayInputStream(encodedCert);
						
						// Get X509 certificate object
						CertificateFactory cf = CertificateFactory.getInstance("X.509");
						cert = (X509Certificate)cf.generateCertificate(isToken);
					}
				}
				 //else
					//throw new WSSecurityException("noXMLSec");
			} //else
				//throw new WSSecurityException("noXMLSig");
			
			// --- Build output ---
			MessageElement certIssuer 	= new MessageElement("", TAG_CERTISSUER);
			MessageElement certSubject 	= new MessageElement("", TAG_CERTSUBJ);
			MessageElement replyTo 		= new MessageElement("", TAG_REPLYTO);
			MessageElement faultTo 		= new MessageElement("", TAG_FAULTTO);
			MessageElement msgID 		= new MessageElement("", TAG_MSGID);
			
			
			if(cert != null) {
				certIssuer.setValue(cert.getIssuerDN().toString());
				certSubject.setValue(cert.getSubjectDN().toString());
			}
			
			if(replyToAddressElement != null)
				replyTo.setValue(replyToAddressElement.getValue());
			
			if(faultToAddressElement != null)
				faultTo.setValue(faultToAddressElement.getValue());
			
			if(msgidElement != null)
				msgID.setValue(msgidElement.getValue());
			
			// Append to body
			msg.getSOAPBody().getFirstChild().appendChild(certIssuer);
			msg.getSOAPBody().getFirstChild().appendChild(certSubject);
			msg.getSOAPBody().getFirstChild().appendChild(replyTo);
			msg.getSOAPBody().getFirstChild().appendChild(faultTo);
			msg.getSOAPBody().getFirstChild().appendChild(msgID);
			
			// NEED THIS TO FLUSH CHANGES!!!
			msg.saveChanges();
			
			System.out.println(msg.getSOAPHeader());
			System.out.println(msg.getSOAPBody());
			
		} catch(Exception e) {
			throw new RuntimeException(e.getMessage());
		}

		return inputModuleData;
	}

	
	// ---------------- BASED ON WSS4J 1.5.4 - SignatureProcessor - verifyXMLSignature ----------------
	// Method that receives the sign xml element and a java keystore
	// and returns the public certificate used in the signature for validation
	public X509Certificate getCertificate(Element elem, KeyStore ks) throws Exception {

		// Get keystore and convert it in a crypto object
		BouncyCastle crypto = new BouncyCastle(null);
		crypto.setKeyStore(ks);
		
		// --------------- verifyXMLSignature modified -------------------------
		XMLSignature sig = null;
		try {
			sig = new XMLSignature(elem, null);
		} catch (XMLSecurityException e2) {
			throw new WSSecurityException(WSSecurityException.FAILED_CHECK, "noXMLSig");
		}
		
		sig.addResourceResolver(EnvelopeIdResolver.getInstance());

		X509Certificate[] certs = null;
		KeyInfo info = sig.getKeyInfo();

		if (info != null) {
			Node node = WSSecurityUtil.getDirectChild(info.getElement(),
					SecurityTokenReference.SECURITY_TOKEN_REFERENCE,
					WSConstants.WSSE_NS);			
			if (node == null) {
				throw new WSSecurityException(
						WSSecurityException.INVALID_SECURITY,
						"unsupportedKeyInfo");
			}
			SecurityTokenReference secRef = new SecurityTokenReference(
					(Element) node);

			// NUNO: Not needed
			//int docHash = elem.getOwnerDocument().hashCode();
			/*
			 * Her we get some information about the document that is being
			 * processed, in partucular the crypto implementation, and already
			 * detected BST that may be used later during dereferencing.
			 */
			// NUNO: Not needed
			//WSDocInfo wsDocInfo = WSDocInfoStore.lookup(docHash);

			if (secRef.containsReference()) {
				Element token = secRef.getTokenElement(elem.getOwnerDocument(),
						null, null); // NUNO: only for SAML assertion the
											// callback will be needed

				/*
				 * at this point check token type: UsernameToken, Binary, SAML
				 * Crypto required only for Binary and SAML
				 */
				QName el = new QName(token.getNamespaceURI(), token.getLocalName());
				if (crypto == null) {
					throw new WSSecurityException(WSSecurityException.FAILURE,
							"noSigCryptoFile");
				}
				if (el.equals(WSSecurityEngine.binaryToken)) {
					// TODO: Use results from BinarySecurityTokenProcessor
					certs = getCertificatesTokenReference((Element) token, crypto);
				}
			} else if (secRef.containsX509Data() || secRef.containsX509IssuerSerial()) {
				certs = secRef.getX509IssuerSerial(crypto);
			} else if (secRef.containsKeyIdentifier()) {
				if (secRef.getKeyIdentifierValueType().equals(
						SecurityTokenReference.ENC_KEY_SHA1_URI)) {

					// NUNO: Not supported
					throw new WSSecurityException(
							WSSecurityException.INVALID_SECURITY,
							"unsupportedKeyInfo", new Object[] { node.toString() });

				} else {
					certs = secRef.getKeyIdentifier(crypto);
				}
			} else {
	                throw new WSSecurityException(
	                     WSSecurityException.INVALID_SECURITY,
	                     "unsupportedKeyInfo", new Object[]{node.toString()});
	        }
		} else {
            if (crypto == null) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "noSigCryptoFile");
            }
            if (crypto.getDefaultX509Alias() != null) {
                certs = crypto.getCertificates(crypto.getDefaultX509Alias());
            } else {
                throw new WSSecurityException(
                        WSSecurityException.INVALID_SECURITY,
                        "unsupportedKeyInfo");
            }
        }
			
		if (certs == null || certs.length == 0 || certs[0] == null) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
        }
		if (certs != null) {
            try {
                certs[0].checkValidity();
            } catch (CertificateExpiredException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK,
                        "invalidCert");
            } catch (CertificateNotYetValidException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK,
                        "invalidCert");
            }
        }

		// NUNO: returning the right certificate
		return certs[0];

//      if(!sig.checkSignatureValue(certs[0]))
//      	throw new RuntimeException("CERT NOT VALID: " + certs[0].toString() + "\n" + sig.getSignatureValue());

	}

	
	// ---------------- WSS4J 1.5.4 UNCHANGED REQUIRED METHODS ----------------
	/**
	 * Extracts the certificate(s) from the Binary Security token reference.
	 * <p/>
	 *
	 * @param elem The element containing the binary security token. This is
	 *             either X509 certificate(s) or a PKIPath.
	 * @return an array of X509 certificates
	 * @throws WSSecurityException
	 */
	public X509Certificate[] getCertificatesTokenReference(Element elem, Crypto crypto)
	        throws WSSecurityException {
	    BinarySecurity token = createSecurityToken(elem);
	    if (token instanceof PKIPathSecurity) {
	        return ((PKIPathSecurity) token).getX509Certificates(false, crypto);
	    } else if (token instanceof X509Security) {
	        X509Certificate cert = ((X509Security) token).getX509Certificate(crypto);
	        X509Certificate[] certs = new X509Certificate[1];
	        certs[0] = cert;
	        return certs;
	    }
	    return null;
	}
	
    /**
     * Checks the <code>element</code> and creates appropriate binary security object.
     *
     * @param element The XML element that contains either a <code>BinarySecurityToken
     *                </code> or a <code>PKIPath</code> element. Other element types a not
     *                supported
     * @return the BinarySecurity object, either a <code>X509Security</code> or a
     *         <code>PKIPathSecurity</code> object.
     * @throws WSSecurityException
     */
    private BinarySecurity createSecurityToken(Element element) throws WSSecurityException {
        BinarySecurity token = new BinarySecurity(element);
        String type = token.getValueType();
        X509Security x509 = null;
        PKIPathSecurity pkiPath = null;

        if (X509Security.X509_V3_TYPE.equals(type)) {
            x509 = new X509Security(element);
            return (BinarySecurity) x509;
        } else if (X509Security.X509_V1_TYPE.equals(type)) {
            x509 = new X509Security(element);
            return (BinarySecurity) x509;
        } else if (PKIPathSecurity.getType().equals(type)) {
            pkiPath = new PKIPathSecurity(element);
            return (BinarySecurity) pkiPath;
        }
        throw new WSSecurityException(WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                "unsupportedBinaryTokenType", new Object[]{type});
    }
    // ---------------- / WSS4J 1.5.4 UNCHANGED REQUIRED METHODS ----------------

}
