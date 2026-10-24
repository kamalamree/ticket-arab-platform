const dotenv = require('dotenv');
const { Pool } = require('pg');
dotenv.config();
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is missing');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const events = [
  { title:'Amr Diab', description:'حفل عمرو دياب في كوكاكولا أرينا بدبي.', venue:'Coca-Cola Arena', city:'دبي', country:'الإمارات', event_date:'2026-11-07T21:00:00+04:00', image_url:'/amr-diab.png', name:'دخول عام', price:295, currency:'AED' },
  { title:'George Wassouf', description:'حفل جورج وسوف ضمن MAYFAIR PRESENTS في الدوحة.', venue:'Doha Golf Club', city:'الدوحة', country:'قطر', event_date:'2026-10-29T20:00:00+03:00', image_url:'/george-wassouf.png', name:'دخول عام', price:265, currency:'QAR' },
  { title:'Elissa', description:'حفل إليسا في مركز عُمان للمؤتمرات والمعارض في مسقط.', venue:'OCEC — Madinat Al Irfan Theatre', city:'مسقط', country:'عُمان', event_date:'2026-11-13T19:00:00+04:00', image_url:'/elissa.png', name:'دخول عام', price:31, currency:'OMR' },
  { title:'Tamer Ashour', description:'حفل تامر عاشور في مركز عُمان للمؤتمرات والمعارض في مسقط.', venue:'OCEC — Madinat Al Irfan Theatre', city:'مسقط', country:'عُمان', event_date:'2026-11-06T21:00:00+04:00', image_url:'/tamer-ashour.png', name:'دخول عام', price:15, currency:'OMR' },
  { title:'TUL8TE', description:'حفل تووليت في حديقة الصحراء بمسرح بيون الدانة. التذاكر المعلنة نفدت، لذلك لا يتوفر مخزون للحجز حاليًا.', venue:'Beyon Al Dana Amphitheatre — Desert Garden', city:'الزلاق', country:'البحرين', event_date:'2026-10-23T18:00:00+03:00', image_url:'/tul8te.png', name:'دخول عام', price:10, currency:'BHD' },
  { title:'Fadel Chaker', description:'حفل فضل شاكر في مسرح أبو بكر سالم ضمن موسم الرياض.', venue:'Abu Bakr Salem Theatre — Boulevard City', city:'الرياض', country:'السعودية', event_date:'2026-10-22T22:00:00+03:00', image_url:'/fadel-chaker.png', name:'دخول عام', price:810, currency:'SAR' },
  { title:'Nancy Ajram', description:'حفل نانسي عجرم في كوكاكولا أرينا بدبي.', venue:'Coca-Cola Arena', city:'دبي', country:'الإمارات', event_date:'2026-10-24T21:00:00+04:00', image_url:'/nancy-ajram.png', name:'دخول عام', price:210, currency:'AED' },
  { title:'Ismael Dawas Band', description:'أمسية موسيقية بحرينية تقليدية لفرقة إسماعيل دواس في دار المحرق.', venue:'Dar Al Muharraq', city:'المحرق', country:'البحرين', event_date:'2026-11-14T20:00:00+03:00', image_url:'/ismael-dawas.png', name:'دخول عام', price:4.9, currency:'BHD' },
];
async function main(){
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  for(const e of events){
   const existing=await client.query('SELECT id FROM events WHERE lower(title)=lower($1) ORDER BY created_at LIMIT 1',[e.title]);
   let eventId;
   if(existing.rowCount){eventId=existing.rows[0].id;await client.query(`UPDATE events SET description=$2,venue=$3,city=$4,country=$5,event_date=$6,image_url=$7,is_active=true,updated_at=now() WHERE id=$1`,[eventId,e.description,e.venue,e.city,e.country,e.event_date,e.image_url]);}
   else{const inserted=await client.query(`INSERT INTO events(title,description,venue,city,country,event_date,image_url) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,[e.title,e.description,e.venue,e.city,e.country,e.event_date,e.image_url]);eventId=inserted.rows[0].id;}
   const existingType=await client.query('SELECT id FROM ticket_types WHERE event_id=$1 AND lower(name)=lower($2) ORDER BY created_at LIMIT 1',[eventId,e.name]);
   if(existingType.rowCount) await client.query(`UPDATE ticket_types SET is_active=true WHERE id=$1`,[existingType.rows[0].id]);
   else await client.query(`INSERT INTO ticket_types(event_id,name,price,currency,quantity_available) VALUES($1,$2,$3,$4,0)`,[eventId,e.name,e.price,e.currency]);
  }
  await client.query('COMMIT');
  console.log(`Imported ${events.length} example events; existing ticket stock was preserved.`);
 }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();await pool.end();}
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
