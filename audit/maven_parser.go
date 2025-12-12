package audit

import (
	"encoding/xml"
	"fmt"
	"os"
)

// MavenDependency represents a Maven dependency from pom.xml
type MavenDependency struct {
	GroupID    string
	ArtifactID string
	Version    string
	Scope      string
}

// PomProject represents the root element of a pom.xml file
type PomProject struct {
	XMLName       xml.Name          `xml:"project"`
	Dependencies  PomDependencies   `xml:"dependencies"`
	Parent        *PomParent        `xml:"parent"`
	Properties    map[string]string `xml:"-"`
	PropertiesRaw xml.Name          `xml:"properties"`
}

// PomParent represents the parent section of a pom.xml
type PomParent struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// PomDependencies represents the dependencies section
type PomDependencies struct {
	Dependency []PomDependency `xml:"dependency"`
}

// PomDependency represents a single dependency in pom.xml
type PomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// ParsePomXML parses a pom.xml file and extracts dependencies
func ParsePomXML(filepath string) ([]MavenDependency, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open pom.xml: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close file: %w", closeErr)
		}
	}()

	var project PomProject
	decoder := xml.NewDecoder(file)
	if err := decoder.Decode(&project); err != nil {
		return nil, fmt.Errorf("failed to parse pom.xml: %w", err)
	}

	var dependencies []MavenDependency
	for _, dep := range project.Dependencies.Dependency {
		// Skip dependencies without version (managed by parent or BOM)
		if dep.Version == "" {
			continue
		}

		// Skip test and provided scope dependencies (optional - could include these)
		// For now, we'll include all dependencies to be thorough
		mavenDep := MavenDependency(dep)

		dependencies = append(dependencies, mavenDep)
	}

	return dependencies, nil
}

// GetMavenPackageName returns the package name in Maven format (groupId:artifactId)
func (d *MavenDependency) GetMavenPackageName() string {
	return fmt.Sprintf("%s:%s", d.GroupID, d.ArtifactID)
}
