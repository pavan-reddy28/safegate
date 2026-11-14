"use strict";

const { analyzeUrl } = require("./urlAnalyzer");
const { normalizeUrl } = require("./urlNormalizer");
const { analyzeDomain } = require("./domainAnalyzer");
const { analyzePath, isSensitivePathSegment } = require("./pathAnalyzer");
const { analyzeQuery } = require("./queryAnalyzer");
const { analyzeScamLures } = require("./scamLureAnalyzer");

module.exports = {
  analyzeUrl,
  normalizeUrl,
  analyzeDomain,
  analyzePath,
  analyzeQuery,
  analyzeScamLures,
  isSensitivePathSegment
};
