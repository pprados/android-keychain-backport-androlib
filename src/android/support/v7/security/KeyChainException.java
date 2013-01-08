package android.support.v7.security;


/**
 * @see android.security.KeyChainException
 * @author pprados
 */
public class KeyChainException extends Exception
{
	private static final long	serialVersionUID	= 1L;
	/**
	 * @see KeyChainException#KeyChainException(String)
	 */
	public KeyChainException(String detailMessage)
	{
		super(detailMessage);
	}
	/**
	 * @see KeyChainException#KeyChainException(String, Throwable)
	 */
	public KeyChainException(String message, Throwable cause)
	{
		super(message,cause);
	}
	/**
	 * @see KeyChainException#KeyChainException(Throwable)
	 */
	public KeyChainException(Throwable cause)
	{
		super(cause);
	}
}
