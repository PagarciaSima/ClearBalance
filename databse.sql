-- MySQL dump 10.13  Distrib 8.0.31, for Win64 (x86_64)
--
-- Host: 127.0.0.1    Database: clearbalance
-- ------------------------------------------------------
-- Server version	8.0.31

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `accountverifications`
--

DROP TABLE IF EXISTS `accountverifications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `accountverifications` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint unsigned NOT NULL,
  `url` varchar(255) NOT NULL,
  `date` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UQ_AccountVerifications_User_Id` (`user_id`),
  UNIQUE KEY `UQ_AccountVerifications_Url` (`url`),
  CONSTRAINT `accountverifications_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=30 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `accountverifications`
--

LOCK TABLES `accountverifications` WRITE;
/*!40000 ALTER TABLE `accountverifications` DISABLE KEYS */;
INSERT INTO `accountverifications` VALUES (4,14,'http://localhost:8080/user/verify/account/c53d8fc6-934b-402e-a9b7-e7e19abb8d2c','2025-12-03 06:46:22.772240'),(6,16,'http://localhost:8080/user/verify/account/41782037-a784-417a-bc39-12358e696fee','2025-12-10 06:05:39.700784'),(7,17,'http://localhost:8080/user/verify/account/10648f3d-7c64-4fa1-89b9-e785ea606e0c','2025-12-10 06:08:05.615631'),(8,18,'http://localhost:8080/user/verify/account/5f7c28df-40da-4a0e-93e5-4b0d405f3e22','2025-12-26 18:58:13.591499'),(9,19,'http://localhost:8080/user/verify/account/9a92a877-78b9-4f91-8b54-df8f7e7a688f','2025-12-26 22:28:41.651067'),(29,92,'http://localhost:4200/auth/user/verify/account/bfb49ceb-ac1c-4c62-89d4-26de657d5152','2026-01-12 15:01:40.660302');
/*!40000 ALTER TABLE `accountverifications` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `customer`
--

DROP TABLE IF EXISTS `customer`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `customer` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `address` varchar(255) DEFAULT NULL,
  `created_at` datetime(6) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `image_url` varchar(255) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `phone` varchar(255) DEFAULT NULL,
  `status` varchar(255) DEFAULT NULL,
  `type` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=107 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `customer`
--

LOCK TABLES `customer` WRITE;
/*!40000 ALTER TABLE `customer` DISABLE KEYS */;
INSERT INTO `customer` VALUES (1,'Rua mayor 53, Salamanca, España','2025-12-11 13:43:18.301000','john.doeedited@example.com','https://images.unsplash.com/photo-1552058544-f2b08422138a?w=500&auto=format&fit=crop&q=60&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxzZWFyY2h8MTJ8fHBlcnNvbnxlbnwwfHwwfHx8MA%3D%3D','John Doe edited','+34 600 123 456','ACTIVE','PERSON'),(2,'Avenida de la Constitución 45, Sevilla, España','2025-12-12 06:09:37.957000','maria.lopez@example.com','https://images.unsplash.com/photo-1438761681033-6461ffad8d80?w=500&auto=format&fit=crop&q=60&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxzZWFyY2h8Mnx8cGVyc29ufGVufDB8fDB8fHww','María López','+34 622 987 321','INACTIVE','COMPANY'),(3,'Piazza Venezia, 10, Roma, Italia','2025-08-23 05:46:05.000000','btrulocke0@ca.gov','http://dummyimage.com/186x100.png/dddddd/000000','Barnebas','245-319-9167','ACTIVE','PERSON'),(4,'1725 Slough Avenue, Scranton, PA, USA','2025-07-28 18:15:20.000000','noxenden1@mapquest.com','http://dummyimage.com/233x100.png/dddddd/000000','Noble','883-747-9076','ACTIVE','PERSON'),(5,'C. de Ruiz de Alarcón, 23, 28014 Madrid, España','2025-04-13 00:53:54.000000','cdoerrling2@macromedia.com','http://dummyimage.com/180x100.png/5fa2dd/ffffff','Cicily','273-616-9604','ACTIVE','PERSON'),(6,'1725 Slough Avenue, Scranton, PA','2025-04-18 18:23:14.000000','gbellam3@tiny.cc','http://dummyimage.com/242x100.png/dddddd/000000','Guenevere','851-884-7895','ACTIVE','PERSON'),(7,'1725 Slough Avenue, Scranton, PA','2025-03-11 11:55:14.000000','rkidston4@telegraph.co.uk','http://dummyimage.com/153x100.png/dddddd/000000','Rubia','405-705-5720','ACTIVE','PERSON'),(8,'1725 Slough Avenue, Scranton, PA','2025-02-15 07:33:40.000000','bcursey5@amazon.co.jp','http://dummyimage.com/110x100.png/5fa2dd/ffffff','Berky','811-340-9210','ACTIVE','PERSON'),(9,'Matilde de la torre 10, Gijón','2025-06-19 06:40:15.000000','griddel6@ihg.com','http://dummyimage.com/226x100.png/5fa2dd/ffffff','Grethel','672-278-0331','ACTIVE','PERSON'),(10,'London SW1A 0AA, Reino Unido','2025-07-15 11:10:23.000000','dansteys7@networkadvertising.org','http://dummyimage.com/244x100.png/5fa2dd/ffffff','Drew','161-680-9280','ACTIVE','PERSON'),(11,'Alt Reinickendorf 4','2025-11-06 19:07:39.000000','scosely8@flavors.me','http://dummyimage.com/165x100.png/cc0000/ffffff','Shawna','718-305-2609','ACTIVE','PERSON'),(12,'20573 Fair Oaks Terrace','2025-10-02 19:52:36.000000','bpetrashkov9@accuweather.com','http://dummyimage.com/247x100.png/cc0000/ffffff','Beauregard','429-213-5745','ACTIVE','PERSON'),(13,'18876 Mitchell Alley','2025-07-23 13:04:26.000000','gwandracha@house.gov','http://dummyimage.com/111x100.png/cc0000/ffffff','Giulia','913-638-3593','ACTIVE','PERSON'),(14,'67451 Becker Way','2025-04-26 10:15:05.000000','plinforthb@wisc.edu','http://dummyimage.com/231x100.png/cc0000/ffffff','Pepita','967-326-6250','ACTIVE','PERSON'),(15,'52 Holmberg Drive','2025-03-06 12:41:12.000000','rfritchlyc@google.pl','http://dummyimage.com/233x100.png/ff4444/ffffff','Reeta','820-843-7724','ACTIVE','PERSON'),(16,'Av de Berlin, 10','2025-01-31 20:39:20.000000','klaunderd@howstuffworks.com','http://dummyimage.com/133x100.png/5fa2dd/ffffff','Kaycee','519-357-9460','ACTIVE','PERSON'),(17,'4 Harper Circle','2025-04-21 01:58:22.000000','acaveille@timesonline.co.uk','http://dummyimage.com/212x100.png/cc0000/ffffff','Andi','520-962-6288','ACTIVE','PERSON'),(18,'414 Old Shore Junction','2025-10-07 20:33:15.000000','nafonsof@pinterest.com','http://dummyimage.com/152x100.png/cc0000/ffffff','Noah','591-655-1631','ACTIVE','PERSON'),(19,'324 South Road','2025-08-10 09:17:58.000000','eroskellyg@gizmodo.com','http://dummyimage.com/144x100.png/dddddd/000000','Erinn','460-215-6637','ACTIVE','PERSON'),(20,'46 Dawn Pass','2025-05-01 20:56:49.000000','espencelayhh@flavors.me','http://dummyimage.com/142x100.png/dddddd/000000','Erin','669-838-6569','ACTIVE','PERSON'),(21,'65 Spaight Way','2025-02-21 04:42:09.000000','ahonackeri@tamu.edu','http://dummyimage.com/245x100.png/dddddd/000000','Ashil','509-111-2994','ACTIVE','PERSON'),(22,'36630 Johnson Crossing','2025-04-28 15:20:54.000000','rsmallridgej@people.com.cn','http://dummyimage.com/100x100.png/cc0000/ffffff','Rhona','228-850-2156','ACTIVE','PERSON'),(23,'33599 Debra Court','2025-11-25 00:57:36.000000','fsanctok@alibaba.com','http://dummyimage.com/130x100.png/5fa2dd/ffffff','Field','132-945-8478','ACTIVE','PERSON'),(24,'1 Delladonna Way','2025-09-18 11:19:03.000000','swriterl@usatoday.com','http://dummyimage.com/173x100.png/ff4444/ffffff','Sisely','385-869-6222','ACTIVE','PERSON'),(25,'1 Hoffman Crossing','2025-07-28 01:24:59.000000','caggusm@prlog.org','http://dummyimage.com/194x100.png/dddddd/000000','Connie','376-472-6487','ACTIVE','PERSON'),(26,'853 Lake View Terrace','2025-06-26 08:33:07.000000','wmartynikhinn@naver.com','http://dummyimage.com/179x100.png/ff4444/ffffff','Wilie','105-163-7741','ACTIVE','PERSON'),(27,'55 Trailsway Center','2025-02-03 01:06:04.000000','mristeo@fastcompany.com','http://dummyimage.com/244x100.png/dddddd/000000','Mohammed','281-749-1973','ACTIVE','PERSON'),(28,'5655 Paget Avenue','2025-03-14 09:24:53.000000','astillmanp@epa.gov','http://dummyimage.com/144x100.png/5fa2dd/ffffff','Augustina','247-499-7733','ACTIVE','PERSON'),(29,'410 Tennyson Alley','2025-06-17 02:41:12.000000','blavensq@comsenz.com','http://dummyimage.com/211x100.png/dddddd/000000','Berni','942-605-8164','ACTIVE','PERSON'),(30,'40570 Kingsford Parkway','2025-08-19 12:24:58.000000','bdemaidr@cloudflare.com','http://dummyimage.com/100x100.png/ff4444/ffffff','Betsey','655-202-5948','ACTIVE','PERSON'),(31,'535 Arkansas Park','2025-11-22 22:16:52.000000','rkilbans@symantec.com','http://dummyimage.com/198x100.png/ff4444/ffffff','Rozina','841-856-5345','ACTIVE','PERSON'),(32,'31 Onsgard Way','2025-05-20 08:06:24.000000','pgelletlyt@washingtonpost.com','http://dummyimage.com/119x100.png/cc0000/ffffff','Pietra','337-553-5577','ACTIVE','PERSON'),(33,'7 Michigan Avenue','2025-08-19 00:48:30.000000','pleckenbyu@latimes.com','http://dummyimage.com/185x100.png/cc0000/ffffff','Pennie','349-671-9788','ACTIVE','PERSON'),(34,'0 New Castle Terrace','2025-11-01 00:22:35.000000','bjarrittv@symantec.com','http://dummyimage.com/223x100.png/cc0000/ffffff','Barri','471-417-5375','ACTIVE','PERSON'),(35,'942 Caliangt Court','2025-06-13 21:03:59.000000','adebiaggiw@php.net','http://dummyimage.com/209x100.png/cc0000/ffffff','Alfi','468-948-2218','ACTIVE','PERSON'),(36,'6073 Duke Trail','2025-07-11 20:17:42.000000','estredderx@mapquest.com','http://dummyimage.com/148x100.png/cc0000/ffffff','Edmon','999-604-5943','ACTIVE','PERSON'),(37,'6 Fremont Drive','2025-10-15 01:54:26.000000','jgillogleyy@soundcloud.com','http://dummyimage.com/203x100.png/5fa2dd/ffffff','Juli','683-655-8140','ACTIVE','PERSON'),(38,'716 Anhalt Junction','2025-09-17 02:59:03.000000','ttatlowz@google.de','http://dummyimage.com/222x100.png/ff4444/ffffff','Tucker','985-511-2770','ACTIVE','PERSON'),(39,'275 Anzinger Center','2025-10-28 19:55:59.000000','nraulstone10@ehow.com','http://dummyimage.com/110x100.png/dddddd/000000','Nealon','988-906-9974','ACTIVE','PERSON'),(40,'33718 Clemons Trail','2025-05-26 04:38:36.000000','haverall11@prweb.com','http://dummyimage.com/171x100.png/dddddd/000000','Hermia','916-393-3771','ACTIVE','PERSON'),(41,'11 Autumn Leaf Parkway','2025-11-15 14:28:19.000000','syakolev12@indiatimes.com','http://dummyimage.com/195x100.png/5fa2dd/ffffff','Sondra','275-807-4369','ACTIVE','PERSON'),(42,'9 Red Cloud Alley','2025-07-15 21:07:36.000000','aalpine13@weebly.com','http://dummyimage.com/246x100.png/5fa2dd/ffffff','Aundrea','142-757-8300','ACTIVE','PERSON'),(43,'030 Mosinee Street','2025-06-01 04:50:15.000000','estreeter14@unicef.org','http://dummyimage.com/210x100.png/ff4444/ffffff','Eddi','941-938-5561','ACTIVE','PERSON'),(44,'5 Sunnyside Trail','2025-03-15 03:55:38.000000','clergan15@yandex.ru','http://dummyimage.com/141x100.png/ff4444/ffffff','Corette','768-206-5810','ACTIVE','PERSON'),(45,'65 Golden Leaf Park','2025-06-20 18:27:27.000000','dpresslie16@naver.com','http://dummyimage.com/212x100.png/5fa2dd/ffffff','Duane','233-279-5414','ACTIVE','PERSON'),(46,'19046 Mcbride Point','2025-03-12 13:43:57.000000','bstorry17@vkontakte.ru','http://dummyimage.com/152x100.png/dddddd/000000','Belicia','206-337-4202','ACTIVE','PERSON'),(47,'82345 Lerdahl Hill','2025-10-18 23:51:25.000000','fabela18@ehow.com','http://dummyimage.com/212x100.png/dddddd/000000','Fionna','882-320-2781','ACTIVE','PERSON'),(48,'5 Karstens Hill','2025-01-24 13:17:15.000000','dhunte19@blogger.com','http://dummyimage.com/219x100.png/5fa2dd/ffffff','Delilah','843-427-6785','ACTIVE','PERSON'),(49,'578 Homewood Point','2025-04-11 19:22:38.000000','btorel1a@ca.gov','http://dummyimage.com/169x100.png/5fa2dd/ffffff','Baxter','493-970-7827','ACTIVE','PERSON'),(50,'8638 Grim Pass','2025-11-21 04:38:56.000000','afratczak1b@adobe.com','http://dummyimage.com/232x100.png/5fa2dd/ffffff','Audra','429-758-7398','ACTIVE','PERSON'),(51,'40882 Elka Way','2025-11-09 09:30:48.000000','lrennick1c@google.ca','http://dummyimage.com/195x100.png/ff4444/ffffff','Linus','414-830-7435','ACTIVE','PERSON'),(52,'1 Kedzie Alley','2025-10-19 22:36:03.000000','sbutterfield1d@exblog.jp','http://dummyimage.com/104x100.png/cc0000/ffffff','Sheff','661-418-7912','ACTIVE','PERSON'),(53,'024 5th Parkway','2025-05-15 01:10:58.000000','kschimann1e@discuz.net','http://dummyimage.com/117x100.png/cc0000/ffffff','Kennan','665-154-7565','ACTIVE','PERSON'),(54,'91742 Karstens Plaza','2025-06-23 12:50:56.000000','fasson1f@newyorker.com','http://dummyimage.com/242x100.png/cc0000/ffffff','Fidole','608-771-5568','ACTIVE','PERSON'),(55,'2867 New Castle Parkway','2025-09-21 15:05:22.000000','rcregin1g@eepurl.com','http://dummyimage.com/199x100.png/cc0000/ffffff','Roz','534-257-6636','ACTIVE','PERSON'),(56,'6000 1st Point','2025-07-23 09:16:58.000000','atrighton1h@hatena.ne.jp','http://dummyimage.com/112x100.png/cc0000/ffffff','Aube','848-456-7452','ACTIVE','PERSON'),(57,'9 Mitchell Drive','2025-07-25 08:19:52.000000','etapsell1i@gravatar.com','http://dummyimage.com/237x100.png/dddddd/000000','Evanne','445-587-6153','ACTIVE','PERSON'),(58,'0 Coleman Junction','2025-12-09 02:24:40.000000','erivitt1j@yelp.com','http://dummyimage.com/242x100.png/dddddd/000000','Emlynne','922-691-6723','ACTIVE','PERSON'),(59,'90 Comanche Drive','2025-07-02 06:05:47.000000','xohoey1k@ifeng.com','http://dummyimage.com/144x100.png/cc0000/ffffff','Xenos','983-994-5484','ACTIVE','PERSON'),(60,'60746 Hansons Circle','2025-01-20 14:20:46.000000','mdracksford1l@exblog.jp','http://dummyimage.com/164x100.png/ff4444/ffffff','Morton','160-565-1922','ACTIVE','PERSON'),(61,'2 Green Ridge Plaza','2025-07-06 00:28:53.000000','ejados1m@hc360.com','http://dummyimage.com/103x100.png/ff4444/ffffff','Evonne','127-206-2470','ACTIVE','PERSON'),(62,'7 Hanover Pass','2025-06-28 17:05:32.000000','msanderson1n@nba.com','http://dummyimage.com/126x100.png/dddddd/000000','Meridith','465-109-1554','ACTIVE','PERSON'),(63,'021 Pawling Street','2025-04-16 15:55:18.000000','kcartwight1o@sitemeter.com','http://dummyimage.com/180x100.png/cc0000/ffffff','Kelly','111-221-5068','ACTIVE','PERSON'),(64,'9304 Hoepker Street','2025-12-07 01:47:51.000000','leby1p@live.com','http://dummyimage.com/105x100.png/5fa2dd/ffffff','Leanor','513-224-3269','ACTIVE','PERSON'),(65,'85554 Di Loreto Road','2025-11-28 15:26:31.000000','mwittleton1q@360.cn','http://dummyimage.com/238x100.png/dddddd/000000','Marshall','720-648-9621','ACTIVE','PERSON'),(66,'6792 Vernon Court','2025-04-26 13:06:49.000000','scoltart1r@army.mil','http://dummyimage.com/242x100.png/5fa2dd/ffffff','Sigmund','678-655-1328','ACTIVE','PERSON'),(67,'56 7th Plaza','2025-08-25 17:58:51.000000','rbaroc1s@pinterest.com','http://dummyimage.com/157x100.png/cc0000/ffffff','Reamonn','360-306-9061','ACTIVE','PERSON'),(68,'9 Buell Street','2025-07-11 05:23:59.000000','cthunnercliff1t@blogtalkradio.com','http://dummyimage.com/237x100.png/ff4444/ffffff','Corilla','648-197-6805','ACTIVE','PERSON'),(69,'4485 Swallow Hill','2024-12-24 20:38:08.000000','jrosenstengel1u@house.gov','http://dummyimage.com/176x100.png/cc0000/ffffff','Jeffrey','502-738-0887','ACTIVE','PERSON'),(70,'315 Lillian Road','2025-02-21 20:10:34.000000','badriaan1v@yelp.com','http://dummyimage.com/142x100.png/cc0000/ffffff','Ber','180-362-5602','ACTIVE','PERSON'),(71,'01 Pond Road','2025-05-17 17:30:03.000000','mviscovi1w@salon.com','http://dummyimage.com/109x100.png/5fa2dd/ffffff','Merv','998-300-1663','ACTIVE','PERSON'),(72,'99 Goodland Circle','2025-03-09 17:31:16.000000','waloigi1x@blogtalkradio.com','http://dummyimage.com/176x100.png/5fa2dd/ffffff','Wilhelmina','766-353-9500','ACTIVE','PERSON'),(73,'2646 Farmco Pass','2025-10-23 00:08:54.000000','akirkland1y@pbs.org','http://dummyimage.com/138x100.png/5fa2dd/ffffff','Alysia','852-319-6307','ACTIVE','PERSON'),(74,'218 Mayer Hill','2025-03-28 21:52:24.000000','vjowitt1z@diigo.com','http://dummyimage.com/215x100.png/dddddd/000000','Valina','674-831-6935','ACTIVE','PERSON'),(75,'601 Lakeland Way','2025-02-24 22:16:45.000000','fbeynon20@nifty.com','http://dummyimage.com/117x100.png/cc0000/ffffff','Fernandina','649-121-1505','ACTIVE','PERSON'),(76,'01 Esch Parkway','2025-03-08 11:33:25.000000','gharmston21@mayoclinic.com','http://dummyimage.com/209x100.png/cc0000/ffffff','Gwenore','761-736-8484','ACTIVE','PERSON'),(77,'99 Warner Court','2025-07-29 03:10:41.000000','agoligher22@odnoklassniki.ru','http://dummyimage.com/228x100.png/ff4444/ffffff','Ardelia','132-342-8861','ACTIVE','PERSON'),(78,'4980 Fair Oaks Pass','2025-02-05 01:42:32.000000','dfassbender23@51.la','http://dummyimage.com/179x100.png/ff4444/ffffff','Dinah','858-245-2477','ACTIVE','PERSON'),(79,'00 Lindbergh Center','2025-07-20 10:55:37.000000','raleshintsev24@yahoo.co.jp','http://dummyimage.com/222x100.png/ff4444/ffffff','Redd','755-197-8575','ACTIVE','PERSON'),(80,'7 Monument Alley','2024-12-21 19:18:08.000000','cdaveren25@home.pl','http://dummyimage.com/128x100.png/5fa2dd/ffffff','Charmane','909-503-4385','ACTIVE','PERSON'),(81,'87 Village Avenue','2025-01-12 17:37:21.000000','mhove26@bizjournals.com','http://dummyimage.com/156x100.png/5fa2dd/ffffff','Mela','881-713-6684','ACTIVE','PERSON'),(82,'79783 Westend Street','2025-02-16 12:37:31.000000','jfrick27@gizmodo.com','http://dummyimage.com/235x100.png/ff4444/ffffff','Jasmin','278-727-7754','ACTIVE','PERSON'),(83,'32 Menomonie Lane','2025-10-10 06:12:40.000000','bjuanes28@ed.gov','http://dummyimage.com/188x100.png/cc0000/ffffff','Bonni','732-844-9218','ACTIVE','PERSON'),(84,'37662 Transport Crossing','2025-09-07 23:47:55.000000','afriel29@wikimedia.org','http://dummyimage.com/212x100.png/dddddd/000000','Aylmer','375-674-6937','ACTIVE','PERSON'),(85,'2 Brickson Park Center','2025-04-11 04:25:31.000000','kroper2a@samsung.com','http://dummyimage.com/210x100.png/dddddd/000000','Kordula','972-769-2915','ACTIVE','PERSON'),(86,'272 Schlimgen Street','2025-10-14 11:16:56.000000','wshotboulte2b@forbes.com','http://dummyimage.com/214x100.png/ff4444/ffffff','Walliw','649-121-8522','ACTIVE','PERSON'),(87,'C. de Ruiz de Alarcón, 23, 28014 Madrid, España','2025-05-15 16:54:54.000000','kmccaughran2c@howstuffworks.com','http://dummyimage.com/194x100.png/5fa2dd/ffffff','Katalin','895-887-4346','ACTIVE','PERSON'),(88,'26 Rowland Alley','2025-09-12 11:04:49.000000','mstranahan2d@live.com','http://dummyimage.com/163x100.png/5fa2dd/ffffff','Mackenzie','504-998-0662','ACTIVE','PERSON'),(89,'15977 Transport Point','2025-02-06 00:27:34.000000','cgladtbach2e@weebly.com','http://dummyimage.com/219x100.png/cc0000/ffffff','Cathlene','718-105-8367','ACTIVE','PERSON'),(90,'60076 Northridge Parkway','2025-08-04 09:49:45.000000','nmacleod2f@smugmug.com','http://dummyimage.com/169x100.png/cc0000/ffffff','Nettie','663-968-0276','ACTIVE','PERSON'),(91,'London SW1A 0AA, Reino Unido','2025-01-23 23:19:16.000000','pclohisey2g@java.com','http://dummyimage.com/122x100.png/cc0000/ffffff','Paxton','828-553-5377','ACTIVE','PERSON'),(92,'8 Myrtle Drive','2025-04-26 06:06:28.000000','jgobat2h@mozilla.com','http://dummyimage.com/210x100.png/ff4444/ffffff','Jessika','204-244-9513','ACTIVE','PERSON'),(93,'9607 Victoria Point','2025-03-30 06:31:10.000000','mwilse2i@boston.com','http://dummyimage.com/148x100.png/5fa2dd/ffffff','Maximilien','495-365-7494','ACTIVE','PERSON'),(94,'Pariser Platz, 10117 Berlin, Alemania','2025-08-10 23:16:52.000000','stoothill2j@amazon.co.uk','http://dummyimage.com/171x100.png/dddddd/000000','Stanislaus','940-783-5808','ACTIVE','PERSON'),(95,'37476 Novick Circle','2025-07-15 19:50:08.000000','asnoddin2k@spiegel.de','http://dummyimage.com/124x100.png/cc0000/ffffff','Aubree','269-806-8084','ACTIVE','PERSON'),(96,'8306 Gina Crossing','2025-05-27 01:43:23.000000','jtanby2l@altervista.org','http://dummyimage.com/249x100.png/ff4444/ffffff','Jean','569-764-8206','ACTIVE','PERSON'),(97,'283 Union Road','2025-02-23 04:54:18.000000','jchetham2m@meetup.com','http://dummyimage.com/220x100.png/cc0000/ffffff','Janina','687-156-4292','ACTIVE','PERSON'),(98,'29 Straubel Pass','2025-09-09 21:59:37.000000','bjuzek2n@ebay.com','http://dummyimage.com/204x100.png/5fa2dd/ffffff','Bryn','573-911-8515','ACTIVE','PERSON'),(99,'8828 Pankratz Circle','2025-09-17 22:58:54.000000','zbossons2o@ucoz.com','http://dummyimage.com/227x100.png/cc0000/ffffff','Zulema','992-685-5316','ACTIVE','PERSON'),(100,'39 Summerview Pass','2025-10-29 01:41:45.000000','vcarr2p@skype.com','http://dummyimage.com/204x100.png/dddddd/000000','Vikky','842-906-7079','ACTIVE','PERSON'),(101,'85 Roth Circle','2025-06-18 04:42:46.000000','ccopelli2q@cnet.com','http://dummyimage.com/220x100.png/ff4444/ffffff','Carlin','244-474-2808','ACTIVE','PERSON'),(102,'4848 Susan Pass','2025-02-10 11:33:32.000000','eslisby2r@1und1.de','http://dummyimage.com/226x100.png/5fa2dd/ffffff','Eryn','205-515-7669','ACTIVE','PERSON'),(103,'Calle Toro 10, Salamanca','2025-12-16 07:31:49.162000','pacoperz@hotmail.com','https://plus.unsplash.com/premium_photo-1678197937465-bdbc4ed95815?w=500&auto=format&fit=crop&q=60&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxzZWFyY2h8NXx8cGVyc29ufGVufDB8fDB8fHww','Paco Perez','691572933','ACTIVE','INDIVIDUAL'),(104,'Museumstraat 1, 1071 XX Amsterdam, Países Bajos','2025-12-16 07:34:32.829000','pacoperz@hotmail.com','https://plus.unsplash.com/premium_photo-1678197937465-bdbc4ed95815?w=500&auto=format&fit=crop&q=60&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxzZWFyY2h8NXx8cGVyc29ufGVufDB8fDB8fHww','asasas','666666666','ACTIVE','INDIVIDUAL'),(105,'Westermarkt 20','2025-12-20 20:48:21.379000','as@hotmail.com','www.qwwqw','asas','6666666','ACTIVE','INDIVIDUAL'),(106,'invented address','2026-01-12 14:58:35.686000','mew@hotmail.com','asasa','New customer','6+915729123','ACTIVE','INSTITUTION');
/*!40000 ALTER TABLE `customer` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `events`
--

DROP TABLE IF EXISTS `events`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `events` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `type` enum('ACCOUNT_SETTINGS_UPDATE','LOGIN_ATTEMPT','LOGIN_ATTEMPT_FAILURE','LOGIN_ATTEMPT_SUCCESS','MFA_UPDATE','PASSWORD_UPDATE','PROFILE_PICTURE_UPDATE','PROFILE_UPDATE','ROLE_UPDATE') NOT NULL,
  `description` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UQ_Events_Type` (`type`),
  CONSTRAINT `events_chk_1` CHECK ((`type` in (_utf8mb4'LOGIN_ATTEMPT',_utf8mb4'LOGIN_ATTEMPT_FAILURE',_utf8mb4'LOGIN_ATTEMPT_SUCCESS',_utf8mb4'PROFILE_UPDATE',_utf8mb4'PROFILE_PICTURE_UPDATE',_utf8mb4'ROLE_UPDATE',_utf8mb4'ACCOUNT_SETTINGS_UPDATE',_utf8mb4'PASSWORD_UPDATE',_utf8mb4'MFA_UPDATE')))
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `events`
--

LOCK TABLES `events` WRITE;
/*!40000 ALTER TABLE `events` DISABLE KEYS */;
INSERT INTO `events` VALUES (1,'LOGIN_ATTEMPT','You tried to log in'),(2,'LOGIN_ATTEMPT_SUCCESS','You tried to log in and you succeeded'),(3,'LOGIN_ATTEMPT_FAILURE','You tried to log in and you failed'),(4,'PROFILE_UPDATE','You updated your profile information'),(5,'PROFILE_PICTURE_UPDATE','You updated your profile picture'),(6,'ROLE_UPDATE','You updated your role and permissions'),(7,'ACCOUNT_SETTINGS_UPDATE','You updated your account settings'),(8,'MFA_UPDATE','You updated your MFA settings'),(9,'PASSWORD_UPDATE','You updated your password');
/*!40000 ALTER TABLE `events` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `invoice`
--

DROP TABLE IF EXISTS `invoice`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `invoice` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `date` datetime(6) DEFAULT NULL,
  `invoice_number` varchar(255) DEFAULT NULL,
  `status` varchar(255) DEFAULT NULL,
  `total` double NOT NULL,
  `customer_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `FKgex6n9u81uvaprblppjsndxth` (`customer_id`),
  CONSTRAINT `FKgex6n9u81uvaprblppjsndxth` FOREIGN KEY (`customer_id`) REFERENCES `customer` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `invoice`
--

LOCK TABLES `invoice` WRITE;
/*!40000 ALTER TABLE `invoice` DISABLE KEYS */;
INSERT INTO `invoice` VALUES (1,'2025-12-22 01:00:00.000000','W8OBYV7R','PAID',3500,1),(2,'2025-12-16 01:00:00.000000','45J0XL0C','PAID',700,15),(3,'2025-12-17 01:00:00.000000','O1DGP3N6','CANCELED',200,18),(4,'2026-01-12 01:00:00.000000','GHUMY3HG','PENDING',1212,16);
/*!40000 ALTER TABLE `invoice` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `invoice_service`
--

DROP TABLE IF EXISTS `invoice_service`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `invoice_service` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `description` varchar(255) DEFAULT NULL,
  `price` double NOT NULL,
  `quantity` int NOT NULL,
  `invoice_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_invoice_service_invoice` (`invoice_id`),
  CONSTRAINT `fk_invoice_service_invoice` FOREIGN KEY (`invoice_id`) REFERENCES `invoice` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `invoice_service`
--

LOCK TABLES `invoice_service` WRITE;
/*!40000 ALTER TABLE `invoice_service` DISABLE KEYS */;
INSERT INTO `invoice_service` VALUES (1,'Web development',2500,1,1),(2,'Seo optimization',1000,1,1),(3,'Grass cutting',200,1,2),(4,'moving services',500,1,2),(5,'Babysitter',200,1,3),(6,'New invoice',1212,1,4);
/*!40000 ALTER TABLE `invoice_service` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resetpasswordverifications`
--

DROP TABLE IF EXISTS `resetpasswordverifications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `resetpasswordverifications` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint unsigned NOT NULL,
  `url` varchar(255) NOT NULL,
  `expiration_date` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UQ_ResetPasswordVerifications_User_Id` (`user_id`),
  UNIQUE KEY `UQ_ResetPasswordVerifications_Url` (`url`),
  CONSTRAINT `resetpasswordverifications_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resetpasswordverifications`
--

LOCK TABLES `resetpasswordverifications` WRITE;
/*!40000 ALTER TABLE `resetpasswordverifications` DISABLE KEYS */;
INSERT INTO `resetpasswordverifications` VALUES (8,15,'http://localhost:4200/auth/user/verify/password/1f34791c-153d-4d08-824b-0214beb5f177','2025-12-30 12:14:29'),(12,91,'http://localhost:4200/auth/user/verify/password/399a8376-4d47-4f90-aad9-f8e6a779f163','2026-01-13 15:16:54');
/*!40000 ALTER TABLE `resetpasswordverifications` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `roles`
--

DROP TABLE IF EXISTS `roles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `roles` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `permission` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UQ_Roles_Name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=622 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `roles`
--

LOCK TABLES `roles` WRITE;
/*!40000 ALTER TABLE `roles` DISABLE KEYS */;
INSERT INTO `roles` VALUES (1,'ROLE_USER','READ:USER,READ:CUSTOMER'),(2,'ROLE_MANAGER','READ:USER,READ:CUSTOMER,UPDATE:USER,UPDATE:CUSTOMER'),(3,'ROLE_ADMIN','READ:USER,READ:CUSTOMER,CREATE:USER,CREATE:CUSTOMER,UPDATE:USER,UPDATE:CUSTOMER'),(4,'ROLE_SYSADMIN','READ:USER,READ:CUSTOMER,CREATE:USER,CREATE:CUSTOMER,UPDATE:USER,UPDATE:CUSTOMER,DELETE:USER,DELETE:CUSTOMER');
/*!40000 ALTER TABLE `roles` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `twofactorverifications`
--

DROP TABLE IF EXISTS `twofactorverifications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `twofactorverifications` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint unsigned NOT NULL,
  `code` varchar(10) NOT NULL,
  `expiration_date` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UQ_TwoFactorVerifications_User_Id` (`user_id`),
  UNIQUE KEY `UQ_TwoFactorVerifications_Code` (`code`),
  CONSTRAINT `twofactorverifications_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `twofactorverifications`
--

LOCK TABLES `twofactorverifications` WRITE;
/*!40000 ALTER TABLE `twofactorverifications` DISABLE KEYS */;
/*!40000 ALTER TABLE `twofactorverifications` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `usereventreports`
--

DROP TABLE IF EXISTS `usereventreports`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `usereventreports` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `user_event_id` bigint unsigned NOT NULL,
  `reason` varchar(255) DEFAULT NULL,
  `comment` text,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `status` enum('PENDING','REJECTED','RESOLVED','REVIEWED') DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_event_id` (`user_event_id`),
  CONSTRAINT `usereventreports_ibfk_1` FOREIGN KEY (`user_event_id`) REFERENCES `userevents` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `usereventreports_chk_1` CHECK ((`status` in (_utf8mb4'PENDING',_utf8mb4'REVIEWED',_utf8mb4'REJECTED',_utf8mb4'RESOLVED')))
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `usereventreports`
--

LOCK TABLES `usereventreports` WRITE;
/*!40000 ALTER TABLE `usereventreports` DISABLE KEYS */;
INSERT INTO `usereventreports` VALUES (1,23,'suspicious login','I did not log in','2025-12-07 17:28:14','PENDING'),(2,22,'test','test','2025-12-07 20:23:09','REVIEWED'),(3,17,'test2','test2','2025-12-07 20:27:06','REJECTED'),(4,103,'reason','comment','2026-01-08 15:12:44','PENDING'),(5,102,'asas','asas','2026-01-08 15:13:54','PENDING'),(6,101,'saa','asa','2026-01-08 15:19:49','REVIEWED'),(7,100,'asasa','asas','2026-01-08 15:24:27','REVIEWED'),(8,99,'asas','asas','2026-01-08 15:27:50','PENDING'),(9,94,'asa','asas','2026-01-08 15:41:02','PENDING'),(10,115,'Login attempt suspicius','asasas','2026-01-12 14:52:48','PENDING');
/*!40000 ALTER TABLE `usereventreports` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `userevents`
--

DROP TABLE IF EXISTS `userevents`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `userevents` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint unsigned NOT NULL,
  `event_id` bigint unsigned NOT NULL,
  `device` varchar(100) DEFAULT NULL,
  `ip_address` varchar(100) DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `event_id` (`event_id`),
  CONSTRAINT `userevents_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `userevents_ibfk_2` FOREIGN KEY (`event_id`) REFERENCES `events` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=121 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `userevents`
--

LOCK TABLES `userevents` WRITE;
/*!40000 ALTER TABLE `userevents` DISABLE KEYS */;
INSERT INTO `userevents` VALUES (5,15,1,'Cloud - PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-03 07:30:54'),(6,15,3,'Cloud - PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-03 07:30:58'),(7,15,1,'Windows NT - Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-03 07:38:04'),(8,15,2,'Windows NT - Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-03 07:38:07'),(9,15,4,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-03 12:42:08'),(10,15,4,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-03 12:46:41'),(11,15,4,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-03 12:48:10'),(12,15,1,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-03 19:37:39'),(13,15,3,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-03 19:37:42'),(14,15,1,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-03 19:37:49'),(15,15,2,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-03 19:37:52'),(16,15,1,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-04 05:57:46'),(17,15,2,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-04 05:57:49'),(18,15,4,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-04 06:37:57'),(19,15,8,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-04 06:40:17'),(20,15,8,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-04 06:40:22'),(21,15,4,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-04 06:40:46'),(22,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-06 17:45:27'),(23,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-06 17:45:30'),(24,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-08 19:31:25'),(25,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-08 19:31:29'),(26,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-08 22:16:01'),(27,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-08 22:16:04'),(28,15,4,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-08 22:29:53'),(29,15,4,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-08 22:33:40'),(30,15,4,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-08 22:36:10'),(31,15,4,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-08 22:41:58'),(32,15,1,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-10 06:18:55'),(33,15,3,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-10 06:18:58'),(34,15,1,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-10 06:19:12'),(35,15,2,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-10 06:19:15'),(36,15,1,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-10 06:23:15'),(37,15,2,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-10 06:23:19'),(38,15,1,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-11 13:42:19'),(39,15,2,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-11 13:42:23'),(40,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-11 14:11:06'),(41,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-11 14:11:09'),(42,15,1,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-12 15:34:42'),(43,15,2,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-12 15:34:44'),(44,15,1,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-14 19:17:01'),(45,15,2,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-14 19:17:05'),(46,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-14 19:32:50'),(47,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-14 19:32:54'),(48,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-16 05:48:11'),(49,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-16 05:48:15'),(50,15,6,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-16 22:45:32'),(51,15,5,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-16 22:46:38'),(52,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-19 06:23:55'),(53,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-19 06:24:03'),(54,15,1,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-22 17:34:39'),(55,15,2,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-22 17:34:42'),(56,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-22 23:01:59'),(57,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-22 23:02:03'),(58,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-24 16:50:14'),(59,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-24 16:50:19'),(60,15,1,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-25 20:04:30'),(61,15,2,'PostmanRuntime - Postman Runtime','0:0:0:0:0:0:0:1','2025-12-25 20:04:37'),(62,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-26 12:59:16'),(63,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-26 12:59:20'),(64,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-29 13:30:58'),(65,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-29 13:31:04'),(66,91,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-30 11:48:53'),(67,91,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-30 11:48:55'),(68,91,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-30 13:53:21'),(69,91,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-30 13:53:28'),(70,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-30 18:37:28'),(71,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-30 18:37:36'),(72,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-31 18:23:22'),(73,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-31 18:23:25'),(74,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-31 18:26:06'),(75,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2025-12-31 18:26:12'),(76,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-02 17:18:43'),(77,15,3,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-02 17:18:50'),(78,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-02 17:19:20'),(79,15,3,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-02 17:19:26'),(80,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-02 17:19:37'),(81,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-02 17:19:43'),(82,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-03 21:36:45'),(83,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-03 21:36:52'),(84,15,1,'PostmanRuntime - Postman Runtime','192.168.96.1','2026-01-05 11:25:01'),(85,15,3,'PostmanRuntime - Postman Runtime','192.168.96.1','2026-01-05 11:25:03'),(86,15,1,'PostmanRuntime - Postman Runtime','192.168.96.1','2026-01-05 11:35:38'),(87,15,2,'PostmanRuntime - Postman Runtime','192.168.96.1','2026-01-05 11:35:39'),(88,15,1,'PostmanRuntime - Postman Runtime','192.168.96.1','2026-01-05 13:51:16'),(89,15,2,'PostmanRuntime - Postman Runtime','192.168.96.1','2026-01-05 13:51:17'),(90,15,1,'Chrome - Desktop','192.168.18.5','2026-01-05 15:02:47'),(91,15,2,'Chrome - Desktop','192.168.18.5','2026-01-05 15:02:51'),(92,15,1,'Chrome - Google Nexus 5','0:0:0:0:0:0:0:1','2026-01-06 18:25:58'),(93,15,2,'Chrome - Google Nexus 5','0:0:0:0:0:0:0:1','2026-01-06 18:26:05'),(94,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-08 07:25:53'),(95,15,3,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-08 07:25:57'),(96,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-08 07:26:06'),(97,15,3,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-08 07:26:10'),(98,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-08 07:26:18'),(99,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-08 07:26:22'),(100,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-08 15:01:50'),(101,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-08 15:01:53'),(102,15,1,'Firefox - Desktop','127.0.0.1','2026-01-08 15:02:26'),(103,15,2,'Firefox - Desktop','127.0.0.1','2026-01-08 15:02:29'),(104,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:21:54'),(105,15,3,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:21:57'),(106,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:22:04'),(107,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:22:07'),(108,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:26:06'),(109,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:26:09'),(110,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:37:26'),(111,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:37:29'),(112,16,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:49:36'),(113,16,3,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:49:38'),(114,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:49:52'),(115,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:49:55'),(116,15,4,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:51:59'),(117,15,4,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:52:05'),(118,15,1,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:57:36'),(119,15,2,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 14:57:39'),(120,15,4,'Chrome - Desktop','0:0:0:0:0:0:0:1','2026-01-12 15:00:27');
/*!40000 ALTER TABLE `userevents` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `userroles`
--

DROP TABLE IF EXISTS `userroles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `userroles` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint unsigned NOT NULL,
  `role_id` bigint unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UQ_UserRoles_User_Id` (`user_id`),
  KEY `role_id` (`role_id`),
  CONSTRAINT `userroles_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `userroles_ibfk_2` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=30 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `userroles`
--

LOCK TABLES `userroles` WRITE;
/*!40000 ALTER TABLE `userroles` DISABLE KEYS */;
INSERT INTO `userroles` VALUES (4,14,4),(5,15,3),(6,16,1),(7,17,1),(8,18,1),(9,19,1),(10,20,1),(11,21,1),(28,91,1),(29,92,1);
/*!40000 ALTER TABLE `userroles` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `first_name` varchar(255) NOT NULL,
  `last_name` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) DEFAULT NULL,
  `address` varchar(255) DEFAULT NULL,
  `phone` varchar(255) DEFAULT NULL,
  `title` varchar(255) DEFAULT NULL,
  `bio` varchar(255) DEFAULT NULL,
  `enabled` tinyint(1) DEFAULT '0',
  `non_locked` tinyint(1) DEFAULT '1',
  `using_mfa` tinyint(1) DEFAULT '0',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `image_url` varchar(255) DEFAULT 'https://cdn-icons-png.flaticon.com/512/149/149071.png',
  PRIMARY KEY (`id`),
  UNIQUE KEY `UQ_Users_Email` (`email`),
  UNIQUE KEY `unique_email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=93 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (14,'john','doe','johndoe@gmail.com','$2a$12$Wv557aAUyxSJx2KDNIXYM.F5xBtOOUn5ZuNhXF4wcVBoQ6H1FWAE.',NULL,NULL,NULL,NULL,1,1,0,'2025-12-03 06:46:22','https://cdn-icons-png.flaticon.com/512/149/149071.png'),(15,'Pablo','García','pablo.garciasimavill4@gmail.com','$2a$12$1sTRN6hAzTmIXwkm485Xw.s5UIHJqi4vYdm39kSMb4wG7zrRqHdoG','Rua mayor 53, Salamanca','123455678','Software Developer','Passionate Java and Angular developer',1,1,0,'2025-12-03 06:49:22',NULL),(16,'Pablo','García','pablo.garciasimavill2@gmail.com','$2a$12$tWIodUuq0pM5MyLDqqgnpeZx5BsWoK/j.Vuo96wnWXWYpBRGFul/K','123 Main Street','123455678','Software Developer','Passionate Java and Angular developer',0,1,0,'2025-12-10 06:05:39','https://cdn-icons-png.flaticon.com/512/149/149071.png'),(17,'Pablo','García','pablo.garciasimavill3@gmail.com','$2a$12$oqFS86YJN2apddg3DZ/oRuKBhZABF8KVqCwu0gHO1.xbJGyjHs5qi','123 Main Street','123455678','Software Developer','Passionate Java and Angular developer',0,1,0,'2025-12-10 06:08:05','https://cdn-icons-png.flaticon.com/512/149/149071.png'),(18,'Alice','Doe','alice@gmail.com','$2a$12$dk5Nq5PhJFYuePXpOs813uipr20X6AXiFHWcV6ew39kb8xcdSz6ry',NULL,NULL,NULL,NULL,0,1,0,'2025-12-26 18:58:13','https://cdn-icons-png.flaticon.com/512/149/149071.png'),(19,'Alice','johnson','alice2@gmail.com','$2a$12$CGQfiNyugHkr0XBeeYzupOfo9eRYTLplOqvfLfVJXxeiulIMVXt/2',NULL,NULL,NULL,NULL,0,1,0,'2025-12-26 22:28:41','https://cdn-icons-png.flaticon.com/512/149/149071.png'),(20,'alice3','doe','alice3@gmail.com','$2a$12$H0NrRJYQDvgPZBAcFCHrTOGZNVYQ1i38gBzQ8nyfRejTOKsWqK/gu',NULL,NULL,NULL,NULL,1,1,0,'2025-12-26 22:29:42','https://cdn-icons-png.flaticon.com/512/149/149071.png'),(21,'alice','doe','alice5@gmail.com','$2a$12$xUMcpRa5ZKA7J5svQO0E9.qsX8BwIi8W.p29C2K/xtA3WehC7Vf3q',NULL,NULL,NULL,NULL,1,1,0,'2025-12-26 22:31:32','https://cdn-icons-png.flaticon.com/512/149/149071.png'),(91,'pablo','garcía','pgarcsim2334@hotmail.com','$2a$12$FYJ618uf9UWqUxLOfNSzKeXNvRau4X2ARpxDsY5/imVZYVMuyhoBu',NULL,NULL,NULL,NULL,1,1,0,'2025-12-30 11:48:01','https://cdn-icons-png.flaticon.com/512/149/149071.png'),(92,'Test','test','test@test.com','$2a$12$mUJOgeaJUZcMdxKqAI857OyUSLR17SP1xHEdygBZ2eK2VLlAwcK.i',NULL,NULL,NULL,NULL,0,1,0,'2026-01-12 15:01:40','https://cdn-icons-png.flaticon.com/512/149/149071.png');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-01-12 15:41:20
