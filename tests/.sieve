require [ "envelope", "subaddress", "fileinto", "reject", "notify", "vacation" ];

if size :under 15 {
	fileinto "Junk";
	stop;
}

if header :is "Subject" "Test Subject 1" {
	fileinto "Trash";
	stop;
}

if header :is "From" "Some string here" {
	fileinto "Trash";
	stop;
}

if header :is "Subject" "Test Subject 2" {
	reject "";
	discard;
}

if header :is "Subject" "Test Subject 3" {
	reject "This is a custom bounce message";
	discard;
}

if header :is "Subject" "Test Subject 4" {
	if header :is "Subject" "No equal to this" {
		fileinto "Trash";
		discard;
	}
	fileinto "Junk"; # This is a comment
}

if allof (header :is "Subject" "Test Subject 5", header :contains "Cc" "example.org") {
	discard;
	stop;
}

if exists "X-Drop-Message" {
	discard;
	stop;
}

if allof (header :is "Subject" "Test Subject 7", header :is "From" "external@example.net") {
	discard;
	stop;
}

if allof (header :is "Subject" "Test Subject 8", header :is "From" "external@example.net") {
	redirect "testuser2@bbs.example.com";
	keep;
}

if allof (header :is "Subject" "Test Subject 9", envelope :all :is "from" "external@example.net") {
	redirect "testuser2@bbs.example.com";
	redirect "testuser@bbs.example.com";
}

if header :is "Subject" "Test Subject 12" {
	vacation :subject "Out of the Office" 
		:days 2
		"I am currently out of the office and will not be available until further notice.";
}
