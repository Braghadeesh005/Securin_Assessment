import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const GetData = () => {
  const [cves, setCves] = useState([]);
  const [totalRecords, setTotalRecords] = useState(0);
  const [resultsPerPage, setResultsPerPage] = useState(10);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const navigate = useNavigate();
  const [filteredCVEs, setFilteredCVEs] = useState([]);

  const [cveId, setCveId] = useState('');
  const [year, setYear] = useState('');
  const [score, setScore] = useState('');
  const [days, setDays] = useState('');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch(`http://localhost:4000/cves/list?perPage=${resultsPerPage}&page=${currentPage}`);
        const data = await response.json();
        setCves(data.cveData);
        setTotalRecords(data.totalCount);
        setTotalPages(Math.ceil(data.totalCount / resultsPerPage));
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    };

    fetchData();
  }, [resultsPerPage, currentPage]);

  const handleFilter = async () => {
    try {
      const response = await axios.get('http://localhost:4000/cves/filter', {
        params: { cveId, year, score, days }
      });
      setFilteredCVEs(response.data);
    } catch (error) {
      console.error('Error filtering CVEs:', error);
    }
  };

  const handleResultsPerPageChange = (e) => {
    setResultsPerPage(Number(e.target.value));
    setCurrentPage(1); // Reset to first page when changing results per page
  };

  const handleRowClick = (cveId) => {
    navigate(`/cves/${cveId}`);
  };

  const handlePageChange = (page) => {
    setCurrentPage(page);
  };

  const pagination = [];
  if (totalPages <= 7) {
    for (let i = 1; i <= totalPages; i++) {
      pagination.push(
        <button key={i} onClick={() => handlePageChange(i)} className={currentPage === i ? 'active' : ''}>
          {i}
        </button>
      );
    }
  } else {
    pagination.push(
      <button key={1} onClick={() => handlePageChange(1)}>
        {1}
      </button>
    );
    pagination.push(<span key="dots1">...</span>);
    const leftBound = Math.max(2, currentPage - 2);
    const rightBound = Math.min(currentPage + 2, totalPages - 1);
    for (let i = leftBound; i <= rightBound; i++) {
      pagination.push(
        <button key={i} onClick={() => handlePageChange(i)} className={currentPage === i ? 'active' : ''}>
          {i}
        </button>
      );
    }
    pagination.push(<span key="dots2">...</span>);
    pagination.push(
      <button key={totalPages} onClick={() => handlePageChange(totalPages)}>
        {totalPages}
      </button>
    );
  }

  const cveDataToRender = filteredCVEs.length > 0 ? filteredCVEs : cves;

  return (
    <div>
      <h1 className='head'>CVE List</h1>
      

      <div className='filter'>
        <input
          type="text"
          placeholder="CVE ID"
          value={cveId}
          onChange={(e) => setCveId(e.target.value)}
        />
        <input
          type="text"
          placeholder="Year"
          value={year}
          onChange={(e) => setYear(e.target.value)}
        />
        <input
          type="text"
          placeholder="Score"
          value={score}
          onChange={(e) => setScore(e.target.value)}
        />
        <input
          type="text"
          placeholder="Last Modified Days"
          value={days}
          onChange={(e) => setDays(e.target.value)}
        />
        <button onClick={handleFilter}>Filter</button>
      </div>
      <p className='total'>Total Records: {totalRecords}</p>
      <table className="cve-table">
        <thead>
          <tr className="heading-row">
            <th>ID</th>
            <th>Source Identifier</th>
            <th>Published</th>
            <th>Last Modified</th>
            <th>Vulnerability Status</th>
          </tr>
        </thead>
        <tbody>
          {cveDataToRender.map(cve => (
            <tr key={cve.id} onClick={() => handleRowClick(cve.id)}>
              <td>{cve.id}</td>
              <td>{cve.sourceIdentifier}</td>
              <td>{cve.published}</td>
              <td>{cve.lastModified}</td>
              <td>{cve.vulnStatus}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className='outer'>
        <label htmlFor="resultsPerPage" className='label'>Results Per Page:</label>
        <select id="resultsPerPage" value={resultsPerPage} onChange={handleResultsPerPageChange}>
          <option value="10">10</option>
          <option value="50">50</option>
          <option value="100">100</option>
        </select>

        <div className="pagination">
          <button onClick={() => handlePageChange(currentPage - 1)} disabled={currentPage === 1}>
            &lt;
          </button>
          {pagination}
          <button onClick={() => handlePageChange(currentPage + 1)} disabled={currentPage === totalPages}>
            &gt;
          </button>
        </div>
      </div>
    </div>
  );
};

export default GetData;
