import React from "react";
import { Routes, Route } from "react-router-dom";
import { BrowserRouter as Router } from "react-router-dom";
import GetData from "./Components/GetData";
import CVEDetails from './Components/CVEDetails';

const Routing = () => {
  return (
    <Routes>
      <Route path="/cves/list" element={<GetData />} />
      <Route path="/cves/:cveId" element={<CVEDetails />} />
    </Routes>
  );
}

const App = () => {
  return (
    <Router>
      <Routing />
    </Router>
  );
}



export default App;
