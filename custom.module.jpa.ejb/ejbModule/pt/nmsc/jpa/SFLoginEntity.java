package pt.nmsc.jpa;

import java.io.Serializable;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

@Entity
@Table(name = "SF_LOGIN_CACHE")
@NamedQueries(value = { @NamedQuery(name = "getCacheContent", query = "SELECT t FROM SFLoginEntity t")})
public class SFLoginEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	private String USERNAME;	
	
	private String SESSIONID;
	private String VALIDITY;
	private String TARGETURL;

	public String getUSERNAME() 				{ return USERNAME; }
	public void setUSERNAME(String uSERNAME) 	{ USERNAME = uSERNAME;}
	
	public String getSESSIONID() 				{ return SESSIONID; }
	public void setSESSIONID(String sESSIONID)	{ SESSIONID = sESSIONID; }
	
	public String getVALIDITY()					{ return VALIDITY; }
	public void setVALIDITY(String vALIDITY) 	{ VALIDITY = vALIDITY; }
	
	public String getTARGETURL() 				{ return TARGETURL; }
	public void setTARGETURL(String tARGETURL) 	{ TARGETURL = tARGETURL; }
}
