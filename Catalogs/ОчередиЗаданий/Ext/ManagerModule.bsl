﻿Функция ДобавитьЗадание(Наименование, Метод, Параметры, Старт) Экспорт
	Оч 		 		= Справочники.ОчередиЗаданий.СоздатьЭлемент();
	Оч.Наименование	= Наименование;
	Оч.Метод 		= Метод;
	Оч.Параметры 	= Параметры;
	Оч.Старт 		= Старт;
	Попытка
		Оч.Записать();	
	Исключение
		ЗаписьЖурналаРегистрации("Справочники.ОчередиЗаданий.ДобавитьЗадани", УровеньЖурналаРегистрации.Ошибка,,СтрШаблон("Наименование=%1, Метод=%2, Параметры=%3, Старт=%4", Наименование, Метод, Параметры, Старт) ,ОписаниеОшибки());
		Возврат "ошибка";
	КонецПопытки;		
	Возврат "";
КонецФункции