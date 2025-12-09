package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
)

// catchallDomain is set via command line argument (empty = use emails.txt)
var catchallDomain string

var firstNames = []string{
	"james", "john", "robert", "michael", "david", "william", "richard", "joseph", "thomas", "christopher",
	"charles", "daniel", "matthew", "anthony", "mark", "donald", "steven", "paul", "andrew", "joshua",
	"kenneth", "kevin", "brian", "george", "timothy", "ronald", "edward", "jason", "jeffrey", "ryan",
	"jacob", "gary", "nicholas", "eric", "jonathan", "stephen", "larry", "justin", "scott", "brandon",
	"benjamin", "samuel", "raymond", "gregory", "frank", "alexander", "patrick", "jack", "dennis", "jerry",
	"mary", "patricia", "jennifer", "linda", "elizabeth", "barbara", "susan", "jessica", "sarah", "karen",
	"lisa", "nancy", "betty", "margaret", "sandra", "ashley", "kimberly", "emily", "donna", "michelle",
	"dorothy", "carol", "amanda", "melissa", "deborah", "stephanie", "rebecca", "sharon", "laura", "cynthia",
	"kathleen", "amy", "angela", "shirley", "anna", "brenda", "pamela", "emma", "nicole", "helen",
	"samantha", "katherine", "christine", "debra", "rachel", "carolyn", "janet", "catherine", "maria", "heather",
}

var lastNames = []string{
	"smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis", "rodriguez", "martinez",
	"hernandez", "lopez", "gonzalez", "wilson", "anderson", "thomas", "taylor", "moore", "jackson", "martin",
	"lee", "perez", "thompson", "white", "harris", "sanchez", "clark", "ramirez", "lewis", "robinson",
	"walker", "young", "allen", "king", "wright", "scott", "torres", "nguyen", "hill", "flores",
	"green", "adams", "nelson", "baker", "hall", "rivera", "campbell", "mitchell", "carter", "roberts",
	"gomez", "phillips", "evans", "turner", "diaz", "parker", "cruz", "edwards", "collins", "reyes",
	"stewart", "morris", "morales", "murphy", "cook", "rogers", "gutierrez", "ortiz", "morgan", "cooper",
	"peterson", "bailey", "reed", "kelly", "howard", "ramos", "kim", "cox", "ward", "richardson",
	"watson", "brooks", "chavez", "wood", "james", "bennett", "gray", "mendoza", "ruiz", "hughes",
	"price", "alvarez", "castillo", "sanders", "patel", "myers", "long", "ross", "foster", "jimenez",
}

// GenerateEmail creates a random email address using the catchall domain.
// Format: firstnamelastname##@domain
func GenerateEmail() string {
	firstName := firstNames[rand.Intn(len(firstNames))]
	lastName := lastNames[rand.Intn(len(lastNames))]
	digits := rand.Intn(100) // 0-99

	return fmt.Sprintf("%s%s%02d@%s", firstName, lastName, digits, catchallDomain)
}

// EmailGenerator generates or reads emails on demand.
type EmailGenerator struct {
	seen      map[string]bool
	fileEmail []string // emails loaded from file (if using file mode)
	index     int
}

// NewEmailGenerator creates a new email generator.
// If catchallDomain is set, generates random emails.
// Otherwise, loads from emails.txt.
func NewEmailGenerator() *EmailGenerator {
	g := &EmailGenerator{
		seen: make(map[string]bool),
	}

	if catchallDomain == "" {
		g.fileEmail = loadEmailsFromFile("emails.txt")
	}

	return g
}

// Next returns the next email address.
func (g *EmailGenerator) Next() string {
	if len(g.fileEmail) > 0 {
		// File mode - return emails sequentially
		if g.index >= len(g.fileEmail) {
			g.index = 0 // wrap around
		}
		email := g.fileEmail[g.index]
		g.index++
		return email
	}

	// Generate mode - create unique random emails
	for {
		email := GenerateEmail()
		lower := strings.ToLower(email)
		if !g.seen[lower] {
			g.seen[lower] = true
			return email
		}
	}
}

// Count returns the number of available emails (for file mode).
func (g *EmailGenerator) Count() int {
	return len(g.fileEmail)
}

// loadEmailsFromFile loads emails from a file, one per line.
func loadEmailsFromFile(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer file.Close()

	var emails []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			emails = append(emails, line)
		}
	}
	return emails
}

// GenerateRandomDOOB generates a random date of birth in YYYY-MM-DD format.
// Returns a date for someone between 21-44 years old.
func GenerateRandomDOOB() string {
	startYear := 1980
	endYear := 2003

	year := startYear + rand.Intn(endYear-startYear+1)
	month := rand.Intn(12) + 1

	// Determine days in month correctly
	daysInMonth := 28
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		daysInMonth = 31
	case 4, 6, 9, 11:
		daysInMonth = 30
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			daysInMonth = 29
		} else {
			daysInMonth = 28
		}
	}

	day := rand.Intn(daysInMonth) + 1

	return fmt.Sprintf("%d-%02d-%02d", year, month, day)
}
