#!/usr/bin/env ruby
# Build a PDF from the concise CA1 Markdown report using only Ruby stdlib
# plus the locally installed wkhtmltopdf binary.

require "cgi"
require "pathname"

source = ARGV[0] || "report/CA1-Submission-Report.md"
output = ARGV[1] || source.sub(/\.md\z/, ".pdf")
html_output = output.sub(/\.pdf\z/, ".html")
base_dir = Pathname.new(source).dirname

def inline_markup(text)
  escaped = CGI.escapeHTML(text)
  escaped = escaped.gsub(/`([^`]+)`/, '<code>\1</code>')
  escaped = escaped.gsub(/\*\*([^*]+)\*\*/, '<strong>\1</strong>')
  escaped.gsub(/\*([^*]+)\*/, '<em>\1</em>')
end

def close_blocks(html, in_list, in_table)
  if in_list
    html << "</ul>\n"
    in_list = false
  end
  if in_table
    html << "</table>\n"
    in_table = false
  end
  [in_list, in_table]
end

lines = File.readlines(source, encoding: "UTF-8")
html = []
in_list = false
in_table = false
pending_table_header = false

lines.each do |raw|
  line = raw.chomp

  if line.strip.empty?
    in_list, in_table = close_blocks(html, in_list, in_table)
    next
  end

  if line.start_with?("|") && line.end_with?("|")
    in_list, = close_blocks(html, in_list, false) if in_list
    cells = line.split("|", -1)[1..-2].map(&:strip)
    if cells.all? { |cell| cell.match?(/\A:?-{3,}:?\z/) }
      pending_table_header = false
      next
    end
    unless in_table
      html << "<table>\n"
      in_table = true
      pending_table_header = true
    end
    tag = pending_table_header ? "th" : "td"
    html << "<tr>#{cells.map { |cell| "<#{tag}>#{inline_markup(cell)}</#{tag}>" }.join}</tr>\n"
    pending_table_header = false
    next
  end

  if line.start_with?("- ")
    in_table = close_blocks(html, false, in_table)[1] if in_table
    unless in_list
      html << "<ul>\n"
      in_list = true
    end
    html << "<li>#{inline_markup(line[2..])}</li>\n"
    next
  end

  in_list, in_table = close_blocks(html, in_list, in_table)

  if (match = line.match(/\A!\[(.*?)\]\((.*?)\)\z/))
    alt = CGI.escapeHTML(match[1])
    path = match[2]
    uri = path.start_with?("/") ? "file://#{path}" : "file://#{(base_dir + path).realpath}"
    html << %(<figure><img src="#{uri}" alt="#{alt}"><figcaption>#{alt}</figcaption></figure>\n)
  elsif (match = line.match(/\A(#+)\s+(.*)\z/))
    level = [match[1].length, 4].min
    html << "<h#{level}>#{inline_markup(match[2])}</h#{level}>\n"
  else
    html << "<p>#{inline_markup(line)}</p>\n"
  end
end

close_blocks(html, in_list, in_table)

document = <<~HTML
  <!doctype html>
  <html>
  <head>
    <meta charset="utf-8">
    <title>CA1 Submission Report</title>
    <style>
      @page { size: A4; margin: 8mm; }
      body {
        color: #111827;
        font-family: Arial, Helvetica, sans-serif;
        font-size: 9px;
        line-height: 1.28;
      }
      h1 { font-size: 19px; margin: 0 0 8px; page-break-after: avoid; }
      h2 { font-size: 14px; margin: 12px 0 5px; border-bottom: 1px solid #cbd5e1; page-break-after: avoid; }
      h3 { font-size: 11px; margin: 8px 0 4px; page-break-after: avoid; }
      h4 { font-size: 10px; margin: 6px 0 3px; page-break-after: avoid; }
      p { margin: 3px 0 5px; }
      ul { margin: 3px 0 6px 16px; padding: 0; }
      li { margin: 2px 0; }
      table { border-collapse: collapse; width: 100%; table-layout: fixed; margin: 5px 0 8px; page-break-inside: avoid; }
      th, td {
        border: 1px solid #cbd5e1;
        font-size: 7.6px;
        padding: 2px 3px;
        vertical-align: top;
        overflow-wrap: anywhere;
        word-break: break-word;
      }
      th { background: #eef2ff; font-weight: 700; }
      code { background: #f1f5f9; padding: 0 2px; font-family: Consolas, monospace; }
      figure { margin: 7px 0; text-align: center; page-break-inside: avoid; }
      img { max-width: 100%; max-height: 115mm; }
      figcaption { color: #475569; font-size: 8px; margin-top: 2px; }
    </style>
  </head>
  <body>
    #{html.join}
  </body>
  </html>
HTML

File.write(html_output, document, encoding: "UTF-8")

unless system("wkhtmltopdf", "--enable-local-file-access", "--quiet", html_output, output)
  warn "wkhtmltopdf failed"
  exit 1
end

puts "Wrote #{output}"
