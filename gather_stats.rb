require 'set'
require 'pp'
require 'ostruct'


def load(hashes_file)
  hashes = {}
  pairs = File.read(hashes_file).lines.map{|l| l=~/([^ ]+) *: hash ([a-f0-9]+)/; [$1,$2]}
  pairs.each{ |(name,hash)| hashes[name] = hash if name }
  return hashes
end

if ARGV[0] == "rerun"
  (0..2).each do |i|
    Thread.new do
      system("go run hasher.go samples/binutils/bin_O#{i}/ld > hashes_O#{i}")
      puts "Done creating hsahes for O#{i}"
    end
  end
  Thread.list.each do |t|
    t.join if t!= Thread.current
  end
end

h0 = load("#{ARGV[1]||""}hashes_O0")
h1 = load("#{ARGV[1]||""}hashes_O1")
h2 = load("#{ARGV[1]||""}hashes_O2")

funs_to_hashes = {}

[h0,h1,h2].each do |hashes|
  hashes.each_pair do |f,h|
    funs_to_hashes[f] ||= []
    funs_to_hashes[f] << h
  end
end

def edit_dist(a,b)
  raise "fail" if a.length != b.length
  (0..a.length).inject(0){|s,e| s+(a[e]==b[e] ? 0 : 1)}
end

pp funs_to_hashes.each_pair.sort_by{|(f,hs)| hs.size}

stats = {}

funs_to_hashes.each_pair do |f,hs|
  curr = stats["#{Set.new(hs).size}/#{hs.size}"] ||= OpenStruct.new
  curr = stats["#{Set.new(hs).size}/#{hs.size}"]

  curr.num||=0
  curr.num+=1
  curr.sum_ed||=0
  curr.num_ed||=0

  hs.to_a.combination(2).each do |(h1,h2)|
    curr.sum_ed += edit_dist(h1,h2)/2
    curr.num_ed += 1
  end
end

stats.each_key do |num_different_hashes|
  curr = stats[num_different_hashes]

  if curr.num_ed > 0
    curr.avg_edit_dist = curr.sum_ed/curr.num_ed.to_f
  end
  curr.delete_field(:num_ed)
  curr.delete_field(:sum_ed)
end

pp stats
