//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vJAXB 2.1.10 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.02.29 at 12:19:02 PM CET 
//


package eu.fp7.secured.xml;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="hspl_list" type="{http://www.example.org/Refinement_Schema}HSPL_list" minOccurs="0"/>
 *         &lt;element name="psa_list" type="{http://www.example.org/Refinement_Schema}PSA_list" minOccurs="0"/>
 *         &lt;element name="solution" type="{http://www.example.org/Refinement_Schema}solutionList" minOccurs="0"/>
 *         &lt;element name="service_graph" type="{http://www.example.org/Refinement_Schema}ServiceGraph" minOccurs="0"/>
 *         &lt;element name="mspl_list" type="{http://www.example.org/Refinement_Schema}MSPL_list" minOccurs="0"/>
 *         &lt;element name="remediation" type="{http://www.example.org/Refinement_Schema}RemediationList" minOccurs="0"/>
 *         &lt;element name="user_psa_list" type="{http://www.example.org/Refinement_Schema}PSA_list" minOccurs="0"/>
 *         &lt;element name="additional_psa_list" type="{http://www.example.org/Refinement_Schema}PSA_list" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="mix" type="{http://www.w3.org/2001/XMLSchema}boolean" default="false" />
 *       &lt;attribute name="isEnforciability" type="{http://www.w3.org/2001/XMLSchema}boolean" default="true" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "hsplList",
    "psaList",
    "solution",
    "serviceGraph",
    "msplList",
    "remediation",
    "userPsaList",
    "additionalPsaList"
})
@XmlRootElement(name = "Mapping")
public class Mapping {

    @XmlElement(name = "hspl_list")
    protected HSPLList hsplList;
    @XmlElement(name = "psa_list")
    protected PSAList psaList;
    protected SolutionList solution;
    @XmlElement(name = "service_graph")
    protected ServiceGraph serviceGraph;
    @XmlElement(name = "mspl_list")
    protected MSPLList msplList;
    protected RemediationList remediation;
    @XmlElement(name = "user_psa_list")
    protected PSAList userPsaList;
    @XmlElement(name = "additional_psa_list")
    protected PSAList additionalPsaList;
    @XmlAttribute
    protected Boolean mix;
    @XmlAttribute
    protected Boolean isEnforciability;

    /**
     * Gets the value of the hsplList property.
     * 
     * @return
     *     possible object is
     *     {@link HSPLList }
     *     
     */
    public HSPLList getHsplList() {
        return hsplList;
    }

    /**
     * Sets the value of the hsplList property.
     * 
     * @param value
     *     allowed object is
     *     {@link HSPLList }
     *     
     */
    public void setHsplList(HSPLList value) {
        this.hsplList = value;
    }

    /**
     * Gets the value of the psaList property.
     * 
     * @return
     *     possible object is
     *     {@link PSAList }
     *     
     */
    public PSAList getPsaList() {
        return psaList;
    }

    /**
     * Sets the value of the psaList property.
     * 
     * @param value
     *     allowed object is
     *     {@link PSAList }
     *     
     */
    public void setPsaList(PSAList value) {
        this.psaList = value;
    }

    /**
     * Gets the value of the solution property.
     * 
     * @return
     *     possible object is
     *     {@link SolutionList }
     *     
     */
    public SolutionList getSolution() {
        return solution;
    }

    /**
     * Sets the value of the solution property.
     * 
     * @param value
     *     allowed object is
     *     {@link SolutionList }
     *     
     */
    public void setSolution(SolutionList value) {
        this.solution = value;
    }

    /**
     * Gets the value of the serviceGraph property.
     * 
     * @return
     *     possible object is
     *     {@link ServiceGraph }
     *     
     */
    public ServiceGraph getServiceGraph() {
        return serviceGraph;
    }

    /**
     * Sets the value of the serviceGraph property.
     * 
     * @param value
     *     allowed object is
     *     {@link ServiceGraph }
     *     
     */
    public void setServiceGraph(ServiceGraph value) {
        this.serviceGraph = value;
    }

    /**
     * Gets the value of the msplList property.
     * 
     * @return
     *     possible object is
     *     {@link MSPLList }
     *     
     */
    public MSPLList getMsplList() {
        return msplList;
    }

    /**
     * Sets the value of the msplList property.
     * 
     * @param value
     *     allowed object is
     *     {@link MSPLList }
     *     
     */
    public void setMsplList(MSPLList value) {
        this.msplList = value;
    }

    /**
     * Gets the value of the remediation property.
     * 
     * @return
     *     possible object is
     *     {@link RemediationList }
     *     
     */
    public RemediationList getRemediation() {
        return remediation;
    }

    /**
     * Sets the value of the remediation property.
     * 
     * @param value
     *     allowed object is
     *     {@link RemediationList }
     *     
     */
    public void setRemediation(RemediationList value) {
        this.remediation = value;
    }

    /**
     * Gets the value of the userPsaList property.
     * 
     * @return
     *     possible object is
     *     {@link PSAList }
     *     
     */
    public PSAList getUserPsaList() {
        return userPsaList;
    }

    /**
     * Sets the value of the userPsaList property.
     * 
     * @param value
     *     allowed object is
     *     {@link PSAList }
     *     
     */
    public void setUserPsaList(PSAList value) {
        this.userPsaList = value;
    }

    /**
     * Gets the value of the additionalPsaList property.
     * 
     * @return
     *     possible object is
     *     {@link PSAList }
     *     
     */
    public PSAList getAdditionalPsaList() {
        return additionalPsaList;
    }

    /**
     * Sets the value of the additionalPsaList property.
     * 
     * @param value
     *     allowed object is
     *     {@link PSAList }
     *     
     */
    public void setAdditionalPsaList(PSAList value) {
        this.additionalPsaList = value;
    }

    /**
     * Gets the value of the mix property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public boolean isMix() {
        if (mix == null) {
            return false;
        } else {
            return mix;
        }
    }

    /**
     * Sets the value of the mix property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setMix(Boolean value) {
        this.mix = value;
    }

    /**
     * Gets the value of the isEnforciability property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public boolean isIsEnforciability() {
        if (isEnforciability == null) {
            return true;
        } else {
            return isEnforciability;
        }
    }

    /**
     * Sets the value of the isEnforciability property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsEnforciability(Boolean value) {
        this.isEnforciability = value;
    }

}
