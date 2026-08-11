require "csv"
require "net/http"
require "uri"
require "openssl"
require "cgi"

INPUT_FILE = "urls.csv"
REPORTS_DIR = "reports"

MAX_REDIRECTS = 5
OPEN_TIMEOUT = 10
READ_TIMEOUT = 15
REQUEST_DELAY = 0.30

EXCLUDED_LINK_PREFIXES = [
  "https://www.smartsurvey.co.uk/s/gov-uk-banner/"
]

def rainbow_teams(value)
  value.to_s.split(" | ").map(&:strip).reject(&:empty?)
end

def report_filename_for_team(team)
  "#{team.downcase}.csv"
end


def normalise_url(url)
  url.to_s.strip
end

def normalise_source_url(url)
  url = normalise_url(url)

  return "" if url.empty?

  if url.start_with?("http://", "https://")
    url
  elsif url.start_with?("/")
    "https://www.gov.uk#{url}"
  else
    "https://#{url}"
  end
end

def internal_url?(url)
  uri = URI.parse(url)
  host = uri.host.to_s.downcase

  [
    "www.gov.uk",
    "www.integration.publishing.service.gov.uk",
    "www.publishing.service.gov.uk"
  ].include?(host)
rescue URI::InvalidURIError
  false
end

def external_url?(url)
  !internal_url?(url)
end

def private_publishing_url?(url)
  uri = URI.parse(url)
  host = uri.host.to_s.downcase

  [
    "www.integration.publishing.service.gov.uk",
    "www.publishing.service.gov.uk"
  ].include?(host)
rescue URI::InvalidURIError
  false
end

def authentication_url?(url)
  uri = URI.parse(url)
  host = uri.host.to_s.downcase

  [
    "dcidm.b2clogin.com",
    "your-account.defra.gov.uk",
    "login.microsoftonline.com"
  ].include?(host)
rescue URI::InvalidURIError
  false
end

def ignored_link?(href)
  return true if href.nil?

  href = href.strip
  return true if href.empty?
  return true if href.start_with?("#")

  ignored_schemes = [
    "mailto:",
    "tel:",
    "javascript:",
    "data:",
    "sms:"
  ]

  ignored_schemes.any? { |scheme| href.downcase.start_with?(scheme) }
end

def excluded_link?(url)
  EXCLUDED_LINK_PREFIXES.any? { |prefix| url.start_with?(prefix) }
end

def clean_anchor_text(anchor_html)
  anchor_html
    .to_s
    .gsub(/<[^>]*>/, " ")
    .gsub(/\s+/, " ")
    .strip
end

def extract_links(html, source_url)
  links = []

  html.scan(/<a\b[^>]*\bhref\s*=\s*(['"])(.*?)\1[^>]*>(.*?)<\/a>/im) do |_quote, href, anchor_html|
    next if ignored_link?(href)

    begin
      absolute_url = URI.join(source_url, CGI.unescapeHTML(href.strip)).to_s

      links << {
        url: absolute_url,
        anchor_text: clean_anchor_text(anchor_html)
      }
    rescue URI::InvalidURIError
      next
    end
  end

  links
end

def valid_http_url?(url)
  uri = URI.parse(url)
  uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
rescue URI::InvalidURIError
  false
end

def request_url(url, method = :head)
  uri = URI.parse(url)

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = uri.scheme == "https"
  http.open_timeout = OPEN_TIMEOUT
  http.read_timeout = READ_TIMEOUT
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER if http.use_ssl?

  path = uri.request_uri
  path = "/" if path.nil? || path.empty?

  request =
    if method == :head
      Net::HTTP::Head.new(path)
    else
      Net::HTTP::Get.new(path)
    end

  request["User-Agent"] =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " \
    "AppleWebKit/537.36 (KHTML, like Gecko) " \
    "Chrome/138.0.0.0 Safari/537.36"

  request["Accept"] =
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"

  request["Accept-Language"] = "en-GB,en;q=0.9"

  http.request(request)
end

def check_url(url, redirects_remaining = MAX_REDIRECTS, redirected = false, auth_journey = false)
  return {
    status: "Invalid URL",
    problem: "URL is not a valid HTTP or HTTPS URL",
    final_url: url,
    redirected: redirected,
    auth_journey: auth_journey
  } unless valid_http_url?(url)

  begin
    response = request_url(url, :head)

    # Some sites block or do not properly support HEAD requests.
    # If HEAD reports a failure, retry with GET before treating the link as broken.
    if response.code.to_i >= 400
      response = request_url(url, :get)
    end

    status_code = response.code.to_i

    if response.is_a?(Net::HTTPRedirection)
      if redirects_remaining <= 0
        return {
          status: status_code,
          problem: "Too many redirects",
          final_url: url,
          redirected: redirected,
          auth_journey: auth_journey
        }
      end

      location = response["location"]
      if location.nil? || location.strip.empty?
        return {
          status: status_code,
          problem: "Redirect without location header",
          final_url: url,
          redirected: redirected,
          auth_journey: auth_journey
        }
      end
      
      redirected_url = URI.join(url, location).to_s
      next_auth_journey = auth_journey || authentication_url?(redirected_url)

      return check_url(
        redirected_url,
        redirects_remaining - 1,
        true,
        next_auth_journey
      )
    end

    if status_code >= 400
      {
        status: status_code,
        problem: response.message,
        final_url: url,
        redirected: redirected,
        auth_journey: auth_journey
      }
    else
      {
        status: status_code,
        problem: nil,
        final_url: url,
        redirected: redirected,
        auth_journey: auth_journey
      }
    end

  rescue SocketError => e
    {
      status: "DNS Error",
      problem: e.message,
      final_url: url,
      redirected: redirected,
      auth_journey: auth_journey
    }

  rescue OpenSSL::SSL::SSLError => e
    {
      status: "SSL Error",
      problem: e.message,
      final_url: url,
      redirected: redirected,
      auth_journey: auth_journey
    }

  rescue Net::OpenTimeout, Net::ReadTimeout => e
    {
      status: "Timeout",
      problem: e.message,
      final_url: url,
      redirected: redirected,
      auth_journey: auth_journey
    }

  rescue URI::InvalidURIError => e
    {
      status: "Invalid URL",
      problem: e.message,
      final_url: url,
      redirected: redirected,
      auth_journey: auth_journey
    }

  rescue StandardError => e
    {
      status: "Error",
      problem: e.message,
      final_url: url,
      redirected: redirected,
      auth_journey: auth_journey
    }
  end
end

def fetch_page(url)
  result = check_url(url)

  if result[:status].is_a?(Integer) && result[:status] >= 400
    return {
      ok: false,
      html: nil,
      problem: "Source page returned #{result[:status]} #{result[:problem]}",
      final_url: result[:final_url],
      redirected: result[:redirected],
      auth_journey: result[:auth_journey]
    }
  end

  if !result[:status].is_a?(Integer)
    return {
      ok: false,
      html: nil,
      problem: "Source page error: #{result[:status]} #{result[:problem]}",
      final_url: result[:final_url],
      redirected: result[:redirected],
      auth_journey: result[:auth_journey]
    }
  end

  begin
    response = request_url(result[:final_url], :get)
    status_code = response.code.to_i

    if status_code >= 400
      {
        ok: false,
        html: nil,
        problem: "Source page returned #{status_code} #{response.message}",
        final_url: result[:final_url],
        redirected: result[:redirected],
        auth_journey: result[:auth_journey]
      }
    else
      {
        ok: true,
        html: response.body,
        problem: nil,
        final_url: result[:final_url],
        redirected: result[:redirected],
        auth_journey: result[:auth_journey]
      }
    end
  rescue StandardError => e
    {
      ok: false,
      html: nil,
      problem: e.message,
      final_url: result[:final_url],
      redirected: result[:redirected],
      auth_journey: result[:auth_journey]
    }
  end
end

def broken_status?(status)
  if status.is_a?(Integer)
    status >= 400 && status != 403
  else
    true
  end
end

def blocked_status?(status)
  status.is_a?(Integer) && status == 403
end

started_at = Time.now

link_issues = []
checked_links_cache = {}
source_pages = []

CSV.foreach(INPUT_FILE, headers: true) do |row|
  source_url = normalise_source_url(row["slug"])

  next if source_url.empty?

  source_pages << {
    url: source_url,
    orgs: row["orgs"],
    rainbow_team: row["rainbow_team"]
  }
end

source_pages.each_with_index do |source_page, index|
  source_url = source_page[:url]

  puts
  puts "Checking source page #{index + 1} of #{source_pages.length}: #{source_url}"

  page = fetch_page(source_url)

  unless page[:ok]
    link_issues << {
      source_page: source_url,
      orgs: source_page[:orgs],
      rainbow_team: source_page[:rainbow_team],
      issue_type: "Source page error",
      problem_link: source_url,
      link_type: internal_url?(source_url) ? "internal source page" : "external source page",
      status: "Source Page Error",
      problem: page[:problem],
      final_url: page[:final_url],
      anchor_text: "",
      redirected: page[:redirected],
      auth_journey: page[:auth_journey]

    }

    puts "  Could not fetch source page: #{page[:problem]}"
    next
  end

  links = extract_links(page[:html], page[:final_url])

  unique_links = {}
  links.each do |link|
    unique_links[link[:url]] ||= link
  end

  puts "  Found #{unique_links.length} unique links"

  unique_links.each_value do |link|
    link_url = link[:url]

    next if excluded_link?(link_url)
    next unless valid_http_url?(link_url)

    result = checked_links_cache[link_url]

    unless result
      result = check_url(link_url)
      checked_links_cache[link_url] = result
      sleep(REQUEST_DELAY)
    end

    status = result[:status]
    problem = result[:problem]

    is_broken = broken_status?(status)
    is_blocked = blocked_status?(status)
    is_private_publishing_link = private_publishing_url?(link_url)
    is_auth_journey = result[:auth_journey]

    next unless is_broken || is_blocked || is_private_publishing_link 

    issue_type =
      if is_private_publishing_link
        "Private publishing link"
      elsif is_auth_journey
        "Authentication journey"
      elsif is_blocked
        "Blocked from checking"
      else
        "Broken link"
      end

      reported_problem =
        if is_private_publishing_link
          "We shouldn't use internal Publisher links, or links to the Integration environment"
        elsif is_auth_journey
          "This link redirects into an authentication journey that cannot be reliably checked by this script."
        elsif is_blocked
          "Blocked, but may work in a browser."
        else
          problem
        end

    link_type = external_url?(link_url) ? "external" : "internal"

    link_issues << {
      source_page: source_url,
      orgs: source_page[:orgs],
      rainbow_team: source_page[:rainbow_team],
      issue_type: issue_type,
      problem_link: link_url,
      link_type: link_type,
      status: status,
      problem: reported_problem,
      final_url: result[:final_url],
      anchor_text: link[:anchor_text],
      redirected: result[:redirected],
      auth_journey: result[:auth_journey]
    }

    puts "  #{issue_type}: #{link_url} (#{status})"
  end
end

teams = ["Red", "Blue", "Green", "Yellow"]

teams.each do |team|
  filename = File.join(REPORTS_DIR, report_filename_for_team(team))

  CSV.open(filename, "w") do |csv|
    csv << [
      "Rainbow Team",
      "Page",
      "Link Text",
      "Link",
      "Status",
      "Problem",
      "Org(s)"
    ]

    link_issues.each do |issue|
      next unless rainbow_teams(issue[:rainbow_team]).include?(team)

      csv << [
        issue[:rainbow_team],
        issue[:source_page],
        issue[:anchor_text],
        issue[:problem_link],
        issue[:status],
        issue[:problem],
        issue[:orgs]
      ]
    end
  end
end

finished_at = Time.now
elapsed_seconds = (finished_at - started_at).round

broken_count = link_issues.count { |issue| issue[:issue_type] == "Broken link" }
blocked_count = link_issues.count { |issue| issue[:issue_type] == "Blocked from checking" }
private_publishing_count = link_issues.count { |issue| issue[:issue_type] == "Private publishing link" }
authentication_journey_count = link_issues.count { |issue| issue[:issue_type] == "Authentication journey" }
source_page_error_count = link_issues.count { |issue| issue[:issue_type] == "Source page error" }

puts
puts "Finished."
puts "Source pages checked: #{source_pages.length}"
puts "Unique links checked: #{checked_links_cache.length}"
puts "Issues found: #{link_issues.length}"
puts "Broken links found: #{broken_count}"
puts "Blocked from checking found: #{blocked_count}"
puts "Private publishing links found: #{private_publishing_count}"
puts "Authentication journeys found: #{authentication_journey_count}"
puts "Source page errors found: #{source_page_error_count}"
puts "Elapsed time: #{elapsed_seconds} seconds"
puts "Reports written to #{REPORTS_DIR}/"
puts "Team reports written: red.csv, blue.csv, green.csv, yellow.csv"