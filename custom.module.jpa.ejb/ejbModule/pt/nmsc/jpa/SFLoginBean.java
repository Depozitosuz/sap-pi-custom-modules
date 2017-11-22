package pt.nmsc.jpa;

import java.util.List;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

/**
 * Session Bean implementation class SFLoginBean
 */
@Stateless
public class SFLoginBean implements SFLoginBeanLocal {

	// Entity manager injection from sfcachedb source
	@PersistenceContext(name = "sfcachedb")
	private EntityManager entityManager;
	
	
	// Create a new SF token in the DB
	public boolean addToken(String username, String sessionID,
								String validity, String targetURL) {
		SFLoginEntity tokenReg = new SFLoginEntity();
		tokenReg.setUSERNAME(username);
		tokenReg.setSESSIONID(sessionID);
		tokenReg.setVALIDITY(validity);
		tokenReg.setTARGETURL(targetURL);
		
		try {
			entityManager.persist(tokenReg);
		} catch(Exception e) { return false; }
		
		return true;
	}
	
	// Get all tokens from the Java DB
	public List<SFLoginEntity> getAllTokens() {
		return entityManager.createNamedQuery("getCacheContent").getResultList();
	}
	
	// Get a token given the service
	public SFLoginEntity getToken(String username) {
		List<SFLoginEntity> tokens = this.getAllTokens();

		for(SFLoginEntity token: tokens)
			if(token.getUSERNAME().equals(username))
				return token;
		
		return null;
	}
	
	// Update a token info
	public boolean updateToken(String username, String sessionID,
			   					String validity, String targetURL) {
		List<SFLoginEntity> tokens = this.getAllTokens();

		for(SFLoginEntity oToken: tokens)
			if(oToken.getUSERNAME().equals(username)) {
				oToken.setSESSIONID(sessionID);
				oToken.setVALIDITY(validity);
				oToken.setTARGETURL(targetURL);
				entityManager.persist(oToken);
				return true;
			}
		
		return false;
	}
	
	// Remove a token from the DB given a username
	public boolean deleteToken(String username) {
		List<SFLoginEntity> tokens = this.getAllTokens();

		for(SFLoginEntity oToken: tokens)
			if(oToken.getUSERNAME().equals(username)) {
				entityManager.remove(oToken);
				return true;
			}
		
		return false;
	}

}