require 'set'
require 'pp'


def load(hashes_file)
  hashes = {}
  pairs = File.read(hashes_file).lines.map{|l| l=~/([^ ]+) *: hash ([a-f0-9]+)/; [$1,$2]}
  pairs.each{ |(name,hash)| hashes[name] = hash }
  return hashes
end

(0..2).each do |i|
  Thread.new do
    system("go run hasher.go samples/binutils/bin_O#{i}/ld > hashes_O#{i}")
  end
end
Thread.list.each do |t|
  t.join if t!= Thread.current
end
h0 = load("hashes_O0")
h1 = load("hashes_O1")
h2 = load("hashes_O2")

funs_to_hashes = {}

[h0,h1,h2].each do |hashes|
  hashes.each_pair do |f,h|
    funs_to_hashes[f] ||= Set.new
    funs_to_hashes[f] << h
  end
end

def edit_dist(a,b)
  raise "fail" if a.length != b.length
  (0..a.length).inject(0){|s,e| s+(a[e]==b[e] ? 1 : 0)}
end

pp funs_to_hashes.each_pair.sort_by{|(f,hs)| hs.size}

stats = {}

funs_to_hashes.each_pair do |f,hs|
  stats[hs.size]||={}

  curr = stats[hs.size]

  curr[:num]||=0
  curr[:num]+=1
  curr[:sum_of_edit_dists]||=0
  curr[:num_of_edit_dists]||=0

  hs.to_a.combination(2).each do |(h1,h2)|
    curr[:sum_of_edit_dists] += edit_dist(h1,h2)/2
    curr[:num_of_edit_dists] += 1
  end
end

stats.each_key do |num_different_hashes|
  curr = stats[num_different_hashes]

  if curr[:num_of_edit_dists] > 0
    curr[:avg_edit_dist] = curr[:sum_of_edit_dists]/curr[:num_of_edit_dists].to_f
  end

  curr.delete(:sum_of_edit_dists)
  curr.delete(:num_of_edit_dists)

end

pp stats
