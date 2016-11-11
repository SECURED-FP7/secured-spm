package eu.fp7.secured.policy.resolution;

import eu.fp7.secured.exception.policy.DuplicateExternalDataException;
import eu.fp7.secured.exception.policy.NoExternalDataException;

public abstract class ExternalDataResolutionStrategy<GenericRule, S> extends GenericConflictResolutionStrategy
{
	public abstract S composeExternalData(GenericRule r1, GenericRule r2) throws NoExternalDataException;
	public abstract void setExternalData(GenericRule rule, S externalData) throws DuplicateExternalDataException;
	public abstract S composeExternalData(GenericRule[] rules) throws NoExternalDataException;
	public abstract S getExternalData(GenericRule rule);
	public abstract void clearExternalData(GenericRule rule);
	public abstract boolean isRuleManaged(GenericRule rule);
}