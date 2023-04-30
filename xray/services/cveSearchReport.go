package services

import (
	"encoding/json"
	"fmt"
	"github.com/jfrog/jfrog-client-go/artifactory/services/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"net/http"
	"time"
)

const (
	// ReportsAPI refer to: https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API#XrayRESTAPI-REPORTS
	CveSearchAPI     = ReportsAPI + "/cveSearch"
	CveSearchListAPI = ReportsAPI + "/cveSearchList"
)

// CveSearchReportContent defines a cve search report content response
type CveSearchReportContent struct {
	CVE        string         `json:"cve"`
	TotalRows  int            `json:"total_rows"`
	ProducedAt time.Time      `json:"produced_at"`
	CreatedBy  string         `json:"created_by"`
	Rows       []CveSearchRow `json:"rows"`
}

// CveSearchRow defines an entry of the report content
type CveSearchRow struct {
	VulnerableComponent string    `json:"vulnerable_component"`
	ImpactedArtifact    string    `json:"impacted_artifact"`
	Path                string    `json:"path"`
	FixedVersions       []string  `json:"fixed_versions"`
	ArtifactScanTime    time.Time `json:"artifact_scan_time"`
	PackageType         string    `json:"package_type"`
	IssueId             string    `json:"issue_id"`
	Summary             string    `json:"summary"`
	Severity            string    `json:"severity"`
	CvssV2Score         float32   `json:"cvss_v2_score,omitempty"`
	CvssV2Vector        string    `json:"cvss_v2_vector,omitempty"`
	CvssV3Score         float32   `json:"cvss_v3_score,omitempty"`
	CvssV3Vector        string    `json:"cvss_v3_vector,omitempty"`
	Provider            string    `json:"provider"`
	Description         string    `json:"description"`
	References          []string  `json:"references"`
	Published           time.Time `json:"published"`
}

// CveSearchReportRequestParams defines a cve search report request
type CveSearchReportRequestParams struct {
	Cve       string          `json:"cve,omitempty"`
	Name      string          `json:"name,omitempty"`
	Filters   CveSearchFilter `json:"filters,omitempty"`
	Resources Resources       `json:"resources,omitempty"`
}

type CveSearchFilter struct {
	VulnerableComponent string     `json:"vulnerable_component,omitempty"`
	ImpactedArtifact    string     `json:"impacted_artifact,omitempty"`
	ScanDate            *TimeRange `json:"scan_date,omitempty"`
}

type CveSearchConsumeFilters struct {
	VulnerableComponent string    `json:"vulnerable_component"`
	ImpactedArtifact    string    `json:"impacted_artifact"`
	ScanDate            time.Time `json:"scan_date"`
}

type ReportListFilters struct {
	Name       string     `json:"name"`
	ReportType string     `json:"type"`
	Status     []string   `json:"status"`
	Author     string     `json:"author"`
	StartTime  *TimeRange `json:"start_time_range"`
}

type TimeRange struct {
	Start *time.Time `json:"start,omitempty"`
	End   *time.Time `json:"end,omitempty"`
}

type Resources struct {
	Repositories       []Repository `json:"repositories,omitempty"`
	ProjectScope       *Projects    `json:"projects,omitempty"`
	BuildScope         *Builds      `json:"builds,omitempty"`
	ReleaseBundleScope *Builds      `json:"release_bundles,omitempty"`
}

type Projects struct {
	Names             []string `json:"names,omitempty"`
	IncludeKeyPattern []string `json:"include_key_patterns,omitempty"`
	ExcludeKeyPattern []string `json:"exclude_key_patterns,omitempty"`
	NumOfLastVersions int      `json:"number_of_latest_versions,omitempty"`
}

type Builds struct {
	IncludePatterns    []string        `json:"include_patterns,omitempty"`
	ExcludePathPattern []string        `json:"exclude_patterns,omitempty"`
	Names              []string        `json:"names,omitempty"`
	BuildsWithRepos    []BuildResource `json:"builds_with_repos,omitempty"`
	NumOfLastVersions  int             `json:"number_of_latest_versions,omitempty"`
}

type BuildResource struct {
	BuildName  string `json:"build"`
	BuildRepo  string `json:"repo"`
	ProjectKey string `json:"project"`
}

type CveReportDetailsList struct {
	TotalReports      int                         `json:"total_reports"`
	ReportDetailsList []*CveReportDetailsListData `json:"reports"`
}

// CveReportDetailsListData defines the detail response for a CVE list report
type CveReportDetailsListData struct {
	Id                      int64     `json:"id"`
	Cve                     string    `json:"cve"`
	Name                    string    `json:"name"`
	Status                  string    `json:"status"`
	TotalArtifacts          int       `json:"total_artifacts"`
	NumOfProcessedArtifacts int       `json:"num_of_processed_artifacts"`
	Progress                int       `json:"progress"`
	NumberOfRows            int       `json:"number_of_rows"`
	StartTime               time.Time `json:"start_time,omitempty"`
	EndTime                 time.Time `json:"end_time,omitempty"`
	Error                   string    `json:"error,omitempty"`
	Author                  string    `json:"author"`
	AbortingUser            string    `json:"aborting_user,omitempty"`
	ProjectKey              string    `json:"project_key,omitempty"`
}

// CveSearch generates a new Xray cve search report
func (rs *ReportService) GenerateCveSearch(req CveSearchReportRequestParams) (*ReportResponse, error) {
	retVal := ReportResponse{}
	httpClientsDetails := rs.XrayDetails.CreateHttpClientDetails()
	utils.SetContentType("application/json", &httpClientsDetails.Headers)

	url := fmt.Sprintf("%s/%s", rs.XrayDetails.GetUrl(), CveSearchAPI)
	content, err := json.Marshal(req)
	if err != nil {
		return &retVal, errorutils.CheckError(err)
	}
	fmt.Println(string(content))
	resp, body, err := rs.client.SendPost(url, content, &httpClientsDetails)
	if err != nil {
		return nil, err
	}
	if err = errorutils.CheckResponseStatusWithBody(resp, body, http.StatusOK, http.StatusCreated); err != nil {
		return &retVal, err
	}

	err = json.Unmarshal(body, &retVal)
	if err != nil {
		return &retVal, errorutils.CheckError(err)
	}

	return &retVal, nil
}

// ListCveSearch retrieves the list of cve search reports
func (rs *ReportService) ListCveSearch(reqPagination ReportPagination, reqFilters ReportListFilters) (*CveReportDetailsList, error) {
	retVal := CveReportDetailsList{}
	httpClientsDetails := rs.XrayDetails.CreateHttpClientDetails()
	utils.SetContentType("application/json", &httpClientsDetails.Headers)

	url := fmt.Sprintf("%s/%s?direction=%s&page_num=%d&num_of_rows=%d&order_by=%s",
		rs.XrayDetails.GetUrl(), CveSearchListAPI, reqPagination.Direction, reqPagination.PageNum, reqPagination.NumRows, reqPagination.OrderBy)
	content, err := json.Marshal(reqFilters)
	if err != nil {
		return &retVal, errorutils.CheckError(err)
	}
	resp, body, err := rs.client.SendPost(url, content, &httpClientsDetails)
	if err != nil {
		return nil, err
	}
	if err = errorutils.CheckResponseStatusWithBody(resp, body, http.StatusOK); err != nil {
		return &retVal, err
	}

	err = json.Unmarshal(body, &retVal)
	if err != nil {
		return &retVal, errorutils.CheckError(err)
	}

	return &retVal, nil
}

// ConsumeCveSearch retrieves the report content of a cve search report
func (rs *ReportService) ConsumeCveSearch(reqParams ReportContentRequestParams, reqFilters CveSearchConsumeFilters) (*CveSearchReportContent, error) {
	retVal := CveSearchReportContent{}
	httpClientsDetails := rs.XrayDetails.CreateHttpClientDetails()
	utils.SetContentType("application/json", &httpClientsDetails.Headers)

	url := fmt.Sprintf("%s/%s/%s?direction=%s&page_num=%d&num_of_rows=%d&order_by=%s",
		rs.XrayDetails.GetUrl(), CveSearchAPI, reqParams.ReportId, reqParams.Direction, reqParams.PageNum, reqParams.NumRows, reqParams.OrderBy)
	content, err := json.Marshal(reqFilters)
	if err != nil {
		return &retVal, errorutils.CheckError(err)
	}
	resp, body, err := rs.client.SendPost(url, content, &httpClientsDetails)
	if err != nil {
		return nil, err
	}
	if err = errorutils.CheckResponseStatusWithBody(resp, body, http.StatusOK); err != nil {
		return &retVal, err
	}

	err = json.Unmarshal(body, &retVal)
	return &retVal, errorutils.CheckError(err)
}
