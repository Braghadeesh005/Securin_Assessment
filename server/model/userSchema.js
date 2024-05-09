const mongoose = require('mongoose');
const { Schema } = mongoose;

const cvssMetricV2Schema = new Schema({
  source: String,
  type: String,
  cvssData: {
    version: String,
    vectorString: String,
    accessVector: String,
    accessComplexity: String,
    authentication: String,
    confidentialityImpact: String,
    integrityImpact: String,
    availabilityImpact: String,
    baseScore: Number
  },
  baseSeverity: String,
  exploitabilityScore: Number,
  impactScore: Number,
  acInsufInfo: Boolean,
  obtainAllPrivilege: Boolean,
  obtainUserPrivilege: Boolean,
  obtainOtherPrivilege: Boolean,
  userInteractionRequired: Boolean
});

const descriptionSchema = new Schema({
  lang: String,
  value: String
});

const weaknessSchema = new Schema({
  source: String,
  type: String,
  description: [descriptionSchema]
});

const cpeMatchSchema = new Schema({
  vulnerable: Boolean,
  criteria: String,
  matchCriteriaId: String
});

const configurationNodeSchema = new Schema({
  operator: String,
  negate: Boolean,
  cpeMatch: [cpeMatchSchema]
});

const configurationSchema = new Schema({
  nodes: [configurationNodeSchema]
});

const referenceSchema = new Schema({
  url: String,
  source: String
});

const cveSchema = new Schema({
  id: String,
  sourceIdentifier: String,
  published: Date,
  lastModified: Date,
  vulnStatus: String,
  descriptions: [descriptionSchema],
  metrics: {
    cvssMetricV2: [cvssMetricV2Schema]
  },
  weaknesses: [weaknessSchema],
  configurations: [configurationSchema],
  references: [referenceSchema]
});

const CVE = mongoose.model('CVE', cveSchema);

module.exports = CVE;
