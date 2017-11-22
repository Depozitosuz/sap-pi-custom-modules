package pt.nmsc.jpa;

import javax.ejb.Local;

import pt.nmsc.jpa.SFLoginEntity;

import java.util.List;

@Local
public interface SFLoginBeanLocal {

	public boolean addToken (String username, String sessionID, String validity, String targetURL);

	public boolean deleteToken (String username);

	public List<SFLoginEntity> getAllTokens ();

	public SFLoginEntity getToken (String username);

	public boolean updateToken (String username, String sessionID, String validity, String targetURL);

}
