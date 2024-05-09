// CVEDetails.js
import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import '../App.css'

const CVEDetails = () => {
  const [cveDetails, setCveDetails] = useState(null);
  const { cveId } = useParams();

  useEffect(() => {
    const fetchCVEData = async () => {
      try {
        const response = await fetch(`http://localhost:4000/cves/${cveId}`);
        const data = await response.json();
        setCveDetails(data);
      } catch (error) {
        console.error('Error fetching CVE details:', error);
      }
    };

    fetchCVEData();
  }, [cveId]);

  if (!cveDetails) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <div>
    <h2><b>Descriptions:</b></h2>
    {cveDetails.descriptions && cveDetails.descriptions.map((description, index) => (
      <div key={index}>
        <p>{description.value}</p>
      </div>
    ))}
  </div>

  <h1>CVSS V2 Metrics:</h1>
  <div className='outer'>
      <p><b>Base Severity: </b>{cveDetails.metrics.cvssMetricV2[0].baseSeverity}</p>
    <p><b>Base Score: </b>{cveDetails.metrics.cvssMetricV2[0].cvssData.baseScore}</p>
  </div>
    <p><b>Vector String: </b>{cveDetails.metrics.cvssMetricV2[0].cvssData.vectorString}</p>
    <div>
  <h1>CVE Details:</h1>
  <table className="cve-table">
    <thead>
      <tr className="heading-row">
        <th>Access Vector</th>
        <th>Access Complexity</th>
        <th>Authentication</th>
        <th>Confidentiality Impact</th>
        <th>Integrity Impact</th>
        <th>Availability Impact</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>{cveDetails.metrics.cvssMetricV2[0].cvssData.accessVector}</td>
        <td>{cveDetails.metrics.cvssMetricV2[0].cvssData.accessComplexity}</td>
        <td>{cveDetails.metrics.cvssMetricV2[0].cvssData.authentication}</td>
        <td>{cveDetails.metrics.cvssMetricV2[0].cvssData.confidentialityImpact}</td>
        <td>{cveDetails.metrics.cvssMetricV2[0].cvssData.integrityImpact}</td>
        <td>{cveDetails.metrics.cvssMetricV2[0].cvssData.availabilityImpact}</td>
      </tr>
    </tbody>
  </table>
</div>
    <h2>Scores:</h2>
    <p><b>Exploitability Score: </b>{cveDetails.metrics.cvssMetricV2[0].exploitabilityScore}</p>
    <p><b>Impact Score: </b>{cveDetails.metrics.cvssMetricV2[0].impactScore}</p>
    <div>
  {cveDetails.configurations && cveDetails.configurations.length > 0 && cveDetails.configurations[0].nodes.map((node, index) => (
    <div key={index}>
      <h2>CPE: {index + 1}</h2>
      <table className="cve-table">
        <thead>
          <tr className="heading-row">
            <th>Vulnerable</th>
            <th>Criteria</th>
            <th>Match Criteria ID</th>
          </tr>
        </thead>
        <tbody>
          {/* Iterate over cpeMatch array */}
          {node.cpeMatch.map((match, matchIndex) => (
            <tr key={matchIndex}>
              <td>{match.vulnerable ? 'Yes' : 'No'}</td>
              <td>{match.criteria}</td>
              <td>{match.matchCriteriaId}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ))}
</div>



    </div>
  );
};

export default CVEDetails;
