package eu.fp7.secured.exception.policy;


/**
 * Thrown when a <tt>Graph</tt> is not a  <tt>semi-lattice</tt>.
 *
 * @author  IO
 */

public class NotInSemiLatticeException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = -8847019385112414653L;

	public NotInSemiLatticeException()
	{}
	
	public NotInSemiLatticeException( String msg ) 
	{
        	super( msg );
	}
}
