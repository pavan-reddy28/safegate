"use strict";

const { analyzeUrl, getGoogleSafePath } = require("./urlAnalyzer");
const { normalizeUrl } = require("./urlNormalizer");
const { analyzeDomain } = require("./domainAnalyzer");
const { analyzePath, isSensitivePathSegment } = require("./pathAnalyzer");
const { analyzeQuery } = require("./queryAnalyzer");

module.exports = {
  analyzeUrl,
  normalizeUrl,
  analyzeDomain,
  analyzePath,
  analyzeQuery,
  isSensitivePathSegment,
  getGoogleSafePath
};
